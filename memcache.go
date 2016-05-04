// Memcache protocol filter implementation
// Could eventually be expanded to accept a configuration struct
// (derived from a YAML config) with options, like which operations
// to allow. Hard-coded for now.

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"time"
)

// Buffer sizes
const (
	readerBufferSize = 32 * 1024
)

// Message types
const (
	MsgRequest  = uint8(0x80)
	MsgResponse = uint8(0x81)
)

// Operation types
const (
	OpGET   = uint8(0x00)
	OpQUIT  = uint8(0x07)
	OpGETQ  = uint8(0x09)
	OpNOOP  = uint8(0x0a)
	OpGETK  = uint8(0x0c)
	OpGETKQ = uint8(0x0d)
	OpSTAT  = uint8(0x10)
)

// Response status values
const (
	NoError      = uint16(0x0000)
	UnknownError = uint16(0x0081)
)

// Header size and field indices
const (
	headerSize    = uint8(24)
	indexMagic    = uint8(0)
	indexOp       = uint8(1)
	indexKeyLen   = uint8(2) // ,3
	indexExtraLen = uint8(4)
	indexDataType = uint8(5)
	indexStatus   = uint8(6)  // ,7
	indexBodyLen  = uint8(8)  // ,9,10,12
	indexOpaque   = uint8(13) // ,14,15,16
	indexCas      = uint8(17) // ,18,19,20,21,22,23,24
)

// Holds buffer and selected fields for Memcache binary protocol header
type binaryHeader struct {
	buf     []byte
	magic   uint8
	op      uint8
	keyLen  uint16
	bodyLen uint32
}

// MemcacheFilter is a filter for the Memcache protocol
// In the future we may (a) make filters resolvable from
// a map by name and (b) allow external customization of
// the exact Memcache operations allowed.
type MemcacheFilter struct {
	latch                          int32
	logPrefix                      string
	src, dst                       net.Conn
	srcReader, dstReader           *bufio.Reader
	limitSrcReader, limitDstReader *io.LimitedReader
	srcBuf, dstBuf                 []byte
}

// NewMemcacheFilter wraps a pipe and filters commands using the
// Memcache protocol
func NewMemcacheFilter(src, dst net.Conn) (m *MemcacheFilter) {
	logPrefix := fmt.Sprintf("filter[memcache]: %s:%s ", src.RemoteAddr().Network(), src.RemoteAddr().String())
	srcReader := bufio.NewReaderSize(src, readerBufferSize)
	dstReader := bufio.NewReaderSize(dst, readerBufferSize)
	return &MemcacheFilter{
		latch:          0,
		logPrefix:      logPrefix,
		src:            src,
		dst:            dst,
		srcReader:      srcReader,
		dstReader:      dstReader,
		limitSrcReader: &io.LimitedReader{R: srcReader, N: readerBufferSize},
		limitDstReader: &io.LimitedReader{R: dstReader, N: readerBufferSize},
		srcBuf:         make([]byte, readerBufferSize),
		dstBuf:         make([]byte, readerBufferSize),
	}
}

// Log a message with our filter's prefix
func (m *MemcacheFilter) logPrintf(format string, v ...interface{}) {
	logger.Print(m.logPrefix, fmt.Sprintf(format, v...))
}

// Convenience method to log an error
func (m *MemcacheFilter) logError(msg string, err error) {
	if err != io.EOF {
		m.logPrintf("%s: %s", msg, err)
	}
}

// Wraps a connection with the Memcache protocol filter
func (m *MemcacheFilter) wrap() {
	defer m.src.Close()
	defer m.dst.Close()
	defer logPipeMsg("closed", m.dst, m.src)
	logPipeMsg("opening", m.dst, m.src)

	// Peek at first byte to determine protocol
	bt, err := m.srcReader.Peek(1)
	if err != nil {
		m.logError("error peeking at first byte from client", err)
		return
	}

	// Determine if src speaks ascii or binary protocol
	if bt[0] == MsgRequest {
		m.wrapBinary()
	} else {
		// Eventually we can implement wrapASCII if needed. For now log and return an error
		m.logPrintf("rejected attempt to connect with ASCII protocol")
		m.src.Write([]byte("ERROR\r\n"))
	}
}

// Wrap the pipes and filter the Memcache binary protocol
func (m *MemcacheFilter) wrapBinary() {
	// Background thread for reading responses from the backend and writing
	// them to the client
	go m.wrapBinaryResponse()

	sleepTime, _ := time.ParseDuration(".01ms")
	header := newHeader()

	// We loop, reading requests from the client, checking each operation, and either:
	// (a) forwarding the request to the backend or (b) discarding the request body
	// and sending back and error response.
	for {
		// Read the binary header fully
		if err := header.decode(m.srcReader); err != nil {
			m.logError("error reading request header from client", err)
			return
		}

		// Convert quiet variants to ensure we always get replies. Otherwise our
		// tracking of oustanding responses will be inconsistent.
		switch header.op {
		case OpGETQ:
			header.setUint8(indexOp, OpGET)
		case OpGETKQ:
			header.setUint8(indexOp, OpGETK)
		}

		switch header.op {

		// Allowed read-only operations
		case OpGET, OpQUIT, OpGETQ, OpNOOP, OpGETK, OpGETKQ, OpSTAT:
			// Increment the latch to indicate we have another outstanding request
			atomic.AddInt32(&m.latch, 1)

			// Copy request header to destination
			if _, err := m.dst.Write(header.buf); err != nil {
				m.logError("error writing request header to the backend", err)
				return
			}

			// Copy request body remaining bytes to destination
			if header.bodyLen > 0 {
				m.limitSrcReader.N = int64(header.bodyLen)
				if _, err := io.CopyBuffer(m.dst, m.limitSrcReader, m.srcBuf); err != nil {
					m.logError("error writing request body to the backend", err)
					return
				}
			}

		default:
			// Drain request and reply with error, then return
			m.srcReader.Discard(int(header.bodyLen))

			// Wait for the background goroutine to flush all server responses
			// to the client.  Then we're clear to write our error response.
			for {
				latchValue := atomic.LoadInt32(&m.latch)
				if latchValue == 0 {
					break
				}
				runtime.Gosched()
				time.Sleep(sleepTime)
			}

			// Construct error response
			msg := "Illegal command. Connection is read-only."
			header.setUint8(indexMagic, MsgResponse)
			header.setUint16(indexStatus, UnknownError)
			header.setUint16(indexKeyLen, 0)
			header.setUint8(indexExtraLen, 0)
			header.setUint8(indexDataType, 0)
			header.setUint32(indexBodyLen, uint32(len(msg)))

			// Write error response header and body to client
			if _, err := m.src.Write(header.buf); err != nil {
				m.logError("error writing error response header to client", err)
				return
			}
			if _, err := io.WriteString(m.src, msg); err != nil {
				m.logError("error writing error response body to client", err)
				return
			}

			// Continue processing requests. Add a flag later for optional connection
			// closing.
		}
	}
}

// In the background we continuously read responses from the backend
// writing them back to the client. When we complete writing a response
// we decrement the "latch". When the latch reaches zero all outstanding
// requests have been responded to.
func (m *MemcacheFilter) wrapBinaryResponse() (err error) {
	defer logPipeMsg("closed", m.src, m.dst)
	logPipeMsg("opening", m.src, m.dst)

	header := newHeader()
	for {
		if err = header.decode(m.dstReader); err != nil {
			m.logError("error reading request header from backend", err)
			break
		}

		if _, err = m.src.Write(header.buf); err != nil {
			m.logError("error copying response header to client", err)
			break
		}

		// Copy response body bytes to client
		if header.bodyLen > 0 {
			m.limitDstReader.N = int64(header.bodyLen)
			if _, err = io.CopyBuffer(m.src, m.limitDstReader, m.dstBuf); err != nil {
				m.logError("error copying response body to client", err)
				break
			}
		}

		// Signal that we've flushed a response back to the client
		atomic.AddInt32(&m.latch, -1)
	}
	return
}

func newHeader() *binaryHeader {
	return &binaryHeader{
		buf: make([]byte, headerSize),
	}
}

func (h *binaryHeader) setUint8(index, value uint8) {
	h.buf[index] = value
}

func (h *binaryHeader) setUint16(index uint8, value uint16) {
	h.buf[index] = byte(value >> 8)
	h.buf[index+1] = byte(value)
}

func (h *binaryHeader) setUint32(index uint8, value uint32) {
	h.buf[index] = byte(value >> 24)
	h.buf[index+1] = byte(value >> 16)
	h.buf[index+2] = byte(value >> 8)
	h.buf[index+3] = byte(value)
}

func (h *binaryHeader) decode(reader io.Reader) (err error) {
	if _, err = io.ReadFull(reader, h.buf); err != nil {
		return err
	}

	// Decode select header fields from the buffer
	h.magic = h.buf[indexMagic]
	h.op = h.buf[indexOp]
	h.keyLen = (uint16(h.buf[indexKeyLen]) << 8) | uint16(h.buf[indexKeyLen+1])
	h.bodyLen = (uint32(h.buf[indexBodyLen]) << 24) |
		(uint32(h.buf[indexBodyLen+1]) << 16) |
		(uint32(h.buf[indexBodyLen+2]) << 8) |
		uint32(h.buf[indexBodyLen+3])
	return
}
