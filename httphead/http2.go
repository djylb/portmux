package httphead

import (
	"encoding/binary"
	"io"
	"slices"
	"strings"
)

// HTTP2Preface is the connection preface that HTTP/2 clients send first.
const HTTP2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// ParseHTTP2 parses data, the first bytes of a cleartext HTTP/2 connection
// with prior knowledge (h2c), and returns its first request: the request's
// :method, :path and :authority become Method, RequestURI and Host, and its
// Proto is "HTTP/2.0". It waits for the connection preface, the SETTINGS
// frame that follows it and the header block of the first request, and
// returns io.ErrUnexpectedEOF until then, and ErrInvalid when data is not
// such a connection.
//
// Each call parses data from the start; an HTTP2Scanner continues where it
// stopped.
func ParseHTTP2(data []byte) (*Request, error) {
	var s HTTP2Scanner
	return s.Scan(data)
}

const (
	http2FrameHeaderLen = 9
	// http2MaxFrameSize is the largest frame a client may send before it
	// learns the server's settings.
	http2MaxFrameSize = 16384
	// http2MaxFrames bounds the frames before the first request.
	http2MaxFrames = 16

	frameHeaders      = 0x1
	frameSettings     = 0x4
	frameContinuation = 0x9

	flagAck        = 0x1
	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20
)

// HTTP2Scanner finds the first request of a cleartext HTTP/2 connection as
// its bytes arrive: each call continues with the frames that were not
// complete before. It bounds the frames before the request and the decoded
// size of its header block. The zero value is ready to use.
type HTTP2Scanner struct {
	pos    int    // start of the next frame
	need   int    // input length at which a NeedMore result can change
	frames int    // frames examined
	stream uint32 // stream whose header block is being collected, or 0
	block  []int  // start and end of each fragment of the header block
}

// Need returns the length that the data must reach before Scan can make
// progress after it returned io.ErrUnexpectedEOF.
func (s *HTTP2Scanner) Need() int { return s.need }

// Scan parses data, the bytes received so far: each call passes the data of
// the previous one followed by the bytes that arrived since. It returns the
// first request, io.ErrUnexpectedEOF until its header block is complete, or
// ErrInvalid.
func (s *HTTP2Scanner) Scan(data []byte) (*Request, error) {
	if s.pos == 0 {
		n := min(len(data), len(HTTP2Preface))
		if string(data[:n]) != HTTP2Preface[:n] {
			return nil, ErrInvalid
		}
		if n < len(HTTP2Preface) {
			s.need = len(data) + 1
			return nil, io.ErrUnexpectedEOF
		}
		s.pos = len(HTTP2Preface)
	}
	for {
		if len(data) < s.pos+http2FrameHeaderLen {
			s.need = s.pos + http2FrameHeaderLen
			return nil, io.ErrUnexpectedEOF
		}
		h := data[s.pos:]
		size := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		typ, flags := h[3], h[4]
		stream := binary.BigEndian.Uint32(h[5:]) & 0x7fffffff
		if size > http2MaxFrameSize {
			return nil, ErrInvalid
		}
		start, end := s.pos+http2FrameHeaderLen, s.pos+http2FrameHeaderLen+size
		if len(data) < end {
			s.need = end
			return nil, io.ErrUnexpectedEOF
		}
		s.pos = end
		s.frames++
		switch {
		case s.frames == 1:
			// The preface is followed by a SETTINGS frame.
			if typ != frameSettings || stream != 0 || flags&flagAck != 0 {
				return nil, ErrInvalid
			}
		case s.stream != 0:
			if typ != frameContinuation || stream != s.stream {
				return nil, ErrInvalid
			}
			s.block = append(s.block, start, end)
			if flags&flagEndHeaders != 0 {
				return s.request(data)
			}
		case typ == frameHeaders:
			if stream%2 == 0 {
				return nil, ErrInvalid // client streams are odd
			}
			if flags&flagPadded != 0 {
				if size == 0 || int(data[start]) >= size {
					return nil, ErrInvalid
				}
				end -= int(data[start])
				start++
			}
			if flags&flagPriority != 0 {
				if start+5 > end {
					return nil, ErrInvalid
				}
				start += 5
			}
			s.stream = stream
			s.block = append(s.block, start, end)
			if flags&flagEndHeaders != 0 {
				return s.request(data)
			}
		case typ == frameContinuation, s.frames > http2MaxFrames:
			return nil, ErrInvalid
		}
	}
}

// request decodes the header block of the first request.
func (s *HTTP2Scanner) request(data []byte) (*Request, error) {
	block := data[s.block[0]:s.block[1]]
	if len(s.block) > 2 {
		block = nil
		for i := 0; i < len(s.block); i += 2 {
			block = append(block, data[s.block[i]:s.block[i+1]]...)
		}
	}
	r := &Request{Proto: "HTTP/2.0"}
	var fields strings.Builder
	var scheme, authority, host string
	var seen [4]bool // :method, :path, :scheme, :authority
	hosts, regular, ok := 0, false, true
	err := newHPACKDecoder().decode(block, func(f hpackField) {
		if !ok {
			return
		}
		// Fields cannot hide line breaks or NUL from the filters
		// (RFC 9113, Section 8.2.1).
		if f.name == "" || strings.ContainsAny(f.name, "\r\n\x00") || strings.ContainsAny(f.value, "\r\n\x00") {
			ok = false
			return
		}
		if f.name[0] == ':' {
			i := slices.Index([]string{":method", ":path", ":scheme", ":authority"}, f.name)
			if regular || i < 0 || seen[i] {
				ok = false // pseudo-header fields come first, once each
				return
			}
			seen[i] = true
			switch i {
			case 0:
				r.Method = f.value
			case 1:
				r.RequestURI = f.value
			case 2:
				scheme = f.value
			case 3:
				authority = f.value
			}
			return
		}
		if strings.ContainsRune(f.name, ':') {
			ok = false
			return
		}
		regular = true
		if f.name == "host" {
			hosts++
			host = f.value
		}
		fields.WriteString(f.name)
		fields.WriteString(": ")
		fields.WriteString(f.value)
		fields.WriteString("\r\n")
	})
	switch {
	case err != nil, !ok, hosts > 1, r.Method == "":
		return nil, ErrInvalid
	case r.Method == "CONNECT":
		if r.RequestURI != "" || scheme != "" || authority == "" {
			return nil, ErrInvalid
		}
	case scheme == "" || r.RequestURI != "*" && !strings.HasPrefix(r.RequestURI, "/"):
		// The path is in origin form, so that it cannot name another
		// host than :authority.
		return nil, ErrInvalid
	}
	r.Host = authority
	if r.Host == "" {
		r.Host = host
	}
	r.fields = fields.String()
	if !r.finish() {
		return nil, ErrInvalid
	}
	return r, nil
}
