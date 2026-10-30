package httphead

import (
	"bytes"
	"errors"
	"io"
	"iter"
	"net/textproto"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/djylb/portmux/hostmatch"
)

// ErrInvalid is returned for data that is not the start of a well-formed
// request head.
var ErrInvalid = errors.New("httphead: not an HTTP request head")

// Request is the head of an HTTP/1.x request, or the first request of a
// cleartext HTTP/2 connection.
type Request struct {
	// Method is the request method, such as "GET".
	Method string
	// RequestURI is the request target exactly as sent.
	RequestURI string
	// Path is the decoded path of the target, resolved as servers resolve it:
	// "." and ".." segments and repeated slashes are removed, and a trailing
	// slash is kept. Routes therefore see "/public/../admin/" as "/admin/".
	// Requests whose path servers resolve differently, with a dot segment
	// that is encoded or has ";" parameters, or with a backslash, and those
	// with '#' in the target are invalid.
	// It is empty for CONNECT requests and "*" for "OPTIONS *".
	Path string
	// Proto is "HTTP/1.0", "HTTP/1.1" or, for HTTP/2, "HTTP/2.0".
	Proto string
	// Host is the authority of an absolute target or of HTTP/2, or else the
	// Host header, possibly with a port. It is empty when the request has
	// neither.
	Host string

	fields     string         // header lines, CRLF or LF terminated
	name       hostmatch.Name // Host prepared for matching
	prepared   bool           // whether name is set
	headerOnce sync.Once
	header     textproto.MIMEHeader
	queryOnce  sync.Once
	query      url.Values
}

// Name returns the host without its port, prepared for matching with
// hostmatch.
func (r *Request) Name() hostmatch.Name {
	if r.prepared {
		return r.name
	}
	return hostmatch.NormalizeHost(r.Host)
}

// Query returns the parameters of the target's query string. The map is
// built on the first call and shared by later calls, so it must not be
// modified.
func (r *Request) Query() url.Values {
	r.queryOnce.Do(func() {
		q := r.RequestURI
		if i := strings.IndexByte(q, '?'); i >= 0 {
			q = q[i+1:]
		} else {
			q = ""
		}
		if i := strings.IndexByte(q, '#'); i >= 0 {
			q = q[:i]
		}
		r.query, _ = url.ParseQuery(q)
	})
	return r.query
}

// Header returns the header fields with canonical keys; convert it with
// http.Header(r.Header()) where net/http is at hand. Like net/http, the Host
// field is moved to Host. The map is built on the first call and shared by
// later calls, so it must not be modified.
func (r *Request) Header() textproto.MIMEHeader {
	r.headerOnce.Do(func() {
		h := make(textproto.MIMEHeader)
		for line := range headerLines(r.fields) {
			colon := strings.IndexByte(line, ':')
			if key := textproto.CanonicalMIMEHeaderKey(line[:colon]); key != "Host" {
				h[key] = append(h[key], trimOWS(line[colon+1:]))
			}
		}
		r.header = h
	})
	return r.header
}

// Values yields the values of the header fields with the given name,
// compared case-insensitively, in order, without building the header map.
func (r *Request) Values(name string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for line := range headerLines(r.fields) {
			colon := strings.IndexByte(line, ':')
			if colon == len(name) && strings.EqualFold(line[:colon], name) {
				if !yield(trimOWS(line[colon+1:])) {
					return
				}
			}
		}
	}
}

// headerLines yields the non-empty header lines of fields without their line
// terminators.
func headerLines(fields string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for fields != "" {
			line, rest, _ := strings.Cut(fields, "\n")
			fields = rest
			line = strings.TrimSuffix(line, "\r")
			if line != "" && !yield(line) {
				return
			}
		}
	}
}

func trimOWS(s string) string {
	return strings.Trim(s, " \t")
}

// Parse parses data, the first bytes of a connection, as the head of an
// HTTP/1.x request: the request line and the header fields up to the empty
// line. Bytes after the head, such as a body, are ignored. It returns
// io.ErrUnexpectedEOF while data is the start of a head, and ErrInvalid when
// data is not one. Requests with more than one Host header or with obsolete
// line folding are invalid, since servers disagree on what they mean.
//
// Each call parses data from the start; a Scanner continues where it
// stopped.
func Parse(data []byte) (*Request, error) {
	var s Scanner
	return s.Scan(data)
}

// maxMethodLen bounds the method token so that long binary input without a
// space is rejected early.
const maxMethodLen = 32

// maxLeadingCRLF bounds the line breaks skipped before the request line.
const maxLeadingCRLF = 4

const (
	scanMethod uint8 = iota
	scanTarget
	scanVersion
	scanFields
)

// Scanner parses an HTTP/1.x request head as its bytes arrive: each call
// continues where the previous one stopped, so input that arrives in small
// pieces is examined once. The zero value is ready to use.
type Scanner struct {
	pos         int // next byte to examine
	lineStart   int // start of the current header line
	methodStart int // after the line breaks before the request line
	methodEnd   int
	targetStart int
	targetEnd   int
	fieldsStart int
	hostStart   int
	hostEnd     int
	hosts       int
	phase       uint8
}

// Need returns the length that the data must reach before Scan can make
// progress after it returned io.ErrUnexpectedEOF.
func (s *Scanner) Need() int { return s.pos + 1 }

// Scan parses data, the bytes received so far: each call passes the data of
// the previous one followed by the bytes that arrived since. It returns the
// request, io.ErrUnexpectedEOF while data is the start of a head, or
// ErrInvalid.
func (s *Scanner) Scan(data []byte) (*Request, error) {
	for s.pos < len(data) {
		c := data[s.pos]
		switch s.phase {
		case scanMethod:
			switch {
			case isTokenChar(c):
				if s.pos++; s.pos-s.methodStart > maxMethodLen {
					return nil, ErrInvalid
				}
			case (c == '\r' || c == '\n') && s.pos == s.methodStart && s.pos < maxLeadingCRLF:
				// Line breaks before the request line are skipped, as RFC
				// 9112, Section 2.2 asks and nginx and Node do.
				s.pos++
				s.methodStart = s.pos
			case c == ' ' && s.pos > s.methodStart:
				s.methodEnd = s.pos
				s.pos++
				s.targetStart = s.pos
				s.phase = scanTarget
			default:
				return nil, ErrInvalid
			}
		case scanTarget:
			switch {
			case c > ' ' && c != 0x7f:
				s.pos++
			case c == ' ' && s.pos > s.targetStart:
				s.targetEnd = s.pos
				s.pos++
				s.phase = scanVersion
			default:
				return nil, ErrInvalid
			}
		case scanVersion:
			const version = "HTTP/1."
			j := s.pos - s.targetEnd - 1
			switch {
			case j < len(version):
				if c != version[j] {
					return nil, ErrInvalid
				}
			case j == len(version):
				if c < '0' || c > '9' {
					return nil, ErrInvalid
				}
			case c == '\n' && (j == len(version)+1 || j == len(version)+2 && data[s.pos-1] == '\r'):
				s.fieldsStart, s.lineStart = s.pos+1, s.pos+1
				s.phase = scanFields
			case c != '\r' || j != len(version)+1:
				return nil, ErrInvalid
			}
			s.pos++
		case scanFields:
			nl := bytes.IndexByte(data[s.pos:], '\n')
			if nl < 0 {
				s.pos = len(data)
				return nil, io.ErrUnexpectedEOF
			}
			nl += s.pos
			s.pos = nl + 1
			line := bytes.TrimSuffix(data[s.lineStart:nl], []byte{'\r'})
			if len(line) == 0 {
				return s.request(data[:s.pos])
			}
			if !s.field(line) {
				return nil, ErrInvalid
			}
			s.lineStart = s.pos
		}
	}
	return nil, io.ErrUnexpectedEOF
}

// field validates one header line and records the Host value. Obsolete line
// folding is rejected, as RFC 9112 allows, and so are control characters in
// values, as net/http rejects them, so that a folded value or one with a bare
// CR cannot mean one thing here and another to the server.
func (s *Scanner) field(line []byte) bool {
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return false
	}
	for _, c := range line[:colon] {
		if !isTokenChar(c) {
			return false
		}
	}
	for _, c := range line[colon+1:] {
		if c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	if colon == 4 && bytes.EqualFold(line[:4], []byte("host")) {
		s.hosts++
		value := line[colon+1:]
		lead := len(value) - len(bytes.TrimLeft(value, " \t"))
		s.hostStart = s.lineStart + colon + 1 + lead
		s.hostEnd = s.hostStart + len(bytes.Trim(value, " \t"))
	}
	return true
}

// request builds the request from the complete head.
func (s *Scanner) request(head []byte) (*Request, error) {
	if s.hosts > 1 {
		return nil, ErrInvalid
	}
	h := string(head)
	r := &Request{
		Method:     h[s.methodStart:s.methodEnd],
		RequestURI: h[s.targetStart:s.targetEnd],
		Proto:      h[s.targetEnd+1 : s.targetEnd+1+len("HTTP/1.1")],
		fields:     h[s.fieldsStart:],
	}
	if s.hosts == 1 {
		r.Host = h[s.hostStart:s.hostEnd]
	}
	if !r.finish() {
		return nil, ErrInvalid
	}
	return r, nil
}

// finish derives Path, and Host for absolute and authority targets, from the
// method and target, and prepares the host for matching. It reports false
// for an invalid target.
func (r *Request) finish() bool {
	target := r.RequestURI
	switch {
	case target == "":
		// Only an HTTP/2 CONNECT request has no target; its authority is
		// the host.
		if r.Method != "CONNECT" {
			return false
		}
	case strings.IndexByte(target, '#') >= 0:
		// Clients send no fragment, and servers disagree on whether '#' ends
		// the path and query, as nginx and Node take it, or is part of them,
		// as net/http takes it.
		return false
	case target[0] == '/':
		raw := target
		if i := strings.IndexByte(raw, '?'); i >= 0 {
			raw = raw[:i]
		}
		p, err := CleanPath(raw)
		if err != nil {
			return false
		}
		r.Path = p
	case target == "*":
		r.Path = "*"
	case r.Method == "CONNECT":
		//goland:noinspection HttpUrlsUsage
		u, err := url.ParseRequestURI("http://" + target)
		if err != nil || u.Host == "" {
			return false
		}
		r.Host = u.Host
	default:
		u, err := url.ParseRequestURI(target)
		if err != nil {
			return false
		}
		if u.Host != "" {
			// Servers that read the Host field, as Node and PHP do, would see
			// another host than the target names.
			if r.Host != "" && hostmatch.NormalizeHost(r.Host) != hostmatch.NormalizeHost(u.Host) {
				return false
			}
			r.Host = u.Host
		}
		p, err := CleanPath(u.EscapedPath())
		if err != nil {
			return false
		}
		r.Path = p
	}
	r.name, r.prepared = hostmatch.NormalizeHost(r.Host), true
	return true
}

// CleanPath decodes an escaped request path, such as the path of an
// origin-form request target, and resolves it as Request.Path is resolved:
// "." and ".." segments and repeated slashes are removed, a trailing slash
// is kept and an empty path becomes "/". It returns ErrInvalid for a path
// that servers resolve differently, as Parse rejects it: a segment that
// becomes "." or ".." only once decoded, a backslash, an empty segment with
// ";" parameters before another segment, an invalid escape, or a control
// character (0x00 to 0x1F and 0x7F) once decoded. A path that
// is clean and has no escapes is returned without allocating.
func CleanPath(escaped string) (string, error) {
	if ambiguousPath(escaped) {
		return "", ErrInvalid
	}
	p := escaped
	if strings.IndexByte(p, '%') >= 0 {
		var err error
		if p, err = url.PathUnescape(p); err != nil {
			return "", ErrInvalid
		}
	}
	for i := 0; i < len(p); i++ {
		if p[i] < ' ' || p[i] == 0x7f {
			return "", ErrInvalid
		}
	}
	return cleanPath(p), nil
}

// HasPathPrefix reports whether path, as CleanPath returns it, is prefix or
// lies below it by whole segments: "/api" has the prefix "/api" and is below
// it, as are "/api/v1" and "/api;v=1", whose ";" starts the parameters that
// Tomcat and Jetty remove, but "/apis" is not; a prefix that ends with "/",
// such as "/api/", takes only paths below it.
func HasPathPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/' || path[len(prefix)] == ';'
}

// ambiguousPath reports whether an escaped path has a segment that servers
// resolve differently: one that becomes "." or ".." only once decoded, split
// at an encoded '/' or stripped of ";" parameters, an empty segment with
// parameters before another segment, or a backslash. nginx, Apache and
// Tomcat resolve such segments and IIS takes a backslash for a slash, while
// net/http's ServeMux and Express match the segments as they are.
func ambiguousPath(escaped string) bool {
	if strings.IndexByte(escaped, '\\') >= 0 || strings.Contains(escaped, "%5C") || strings.Contains(escaped, "%5c") {
		return true
	}
	for seg, rest, more := "", escaped, true; more; {
		seg, rest, more = strings.Cut(rest, "/")
		if seg == "." || seg == ".." || !strings.ContainsAny(seg, "%;") {
			continue
		}
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			return true
		}
		for piece, dRest, dMore := "", decoded, true; dMore; {
			piece, dRest, dMore = strings.Cut(dRest, "/")
			name, _, params := strings.Cut(piece, ";")
			if name == "." || name == ".." || params && name == "" && (dMore || more) {
				return true
			}
		}
	}
	return false
}

// cleanPath resolves "." and ".." segments and repeated slashes as servers
// do, keeping a trailing slash. An empty path becomes "/". Clean paths are
// returned without allocating.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		if len(c)+1 == len(p) && p[:len(c)] == c {
			return p
		}
		return c + "/"
	}
	return c
}

func isTokenChar(c byte) bool {
	return c < 0x80 && tokenTable[c]
}

var tokenTable = func() (t [128]bool) {
	for c := 'a'; c <= 'z'; c++ {
		t[c], t[c-'a'+'A'] = true, true
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for _, c := range "!#$%&'*+-.^_`|~" {
		t[c] = true
	}
	return t
}()
