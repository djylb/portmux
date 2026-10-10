package tlshello

import (
	"encoding/binary"
	"errors"
	"io"
	"slices"

	"github.com/djylb/portmux/hostmatch"
)

// ErrInvalid is returned for data that is not the start of a well-formed TLS
// ClientHello.
var ErrInvalid = errors.New("tlshello: not a TLS ClientHello")

// Hello is the content of a TLS ClientHello that routing and
// fingerprinting use. Lists keep the client's order and include GREASE
// values; the lists of absent extensions are nil.
type Hello struct {
	// ServerName is the SNI host name exactly as sent, or empty without SNI.
	ServerName string
	// ALPN lists the offered application protocols in client preference
	// order.
	ALPN []string
	// SupportedVersions lists the versions from the supported_versions
	// extension.
	SupportedVersions []uint16
	// CipherSuites lists the offered cipher suites.
	CipherSuites []uint16
	// Extensions lists the extension types in the order they were sent.
	Extensions []uint16
	// SupportedGroups lists the groups of the supported_groups extension,
	// formerly elliptic_curves.
	SupportedGroups []uint16
	// SignatureSchemes lists the signature_algorithms extension.
	SignatureSchemes []uint16
	// PointFormats lists the ec_point_formats extension.
	PointFormats []uint8
	name         hostmatch.Name // ServerName prepared for matching
	// Version is the legacy_version field. TLS 1.3 clients send 0x0303 here
	// and list their real versions in SupportedVersions.
	Version uint16
	// ECH reports an encrypted_client_hello extension. Browsers send one
	// with random content, a GREASE ECH, when they have no ECH configuration
	// for the server; only with a real one is ServerName the public name of
	// the outer hello rather than the name the client wants.
	ECH      bool
	prepared bool // whether name is set
}

// Name returns ServerName prepared for matching with hostmatch.
func (h *Hello) Name() hostmatch.Name {
	if h.prepared {
		return h.name
	}
	return hostmatch.Normalize(h.ServerName)
}

// MaxVersion returns the highest TLS version the client offers: the highest
// of SupportedVersions, leaving out GREASE values, or else Version.
func (h *Hello) MaxVersion() uint16 {
	top := uint16(0)
	for _, v := range h.SupportedVersions {
		if !IsGREASE(v) && v > top {
			top = v
		}
	}
	if top == 0 {
		return h.Version
	}
	return top
}

// IsGREASE reports whether v is one of the reserved values that clients send
// to keep servers tolerant, 0x0a0a, 0x1a1a and so on (RFC 8701), in the
// lists of versions, cipher suites, extensions, groups and signature
// algorithms.
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

const (
	recordHeaderLen          = 5
	recordTypeHandshake      = 22
	maxRecordPlaintext       = 1 << 14
	handshakeHeaderLen       = 4
	handshakeTypeClientHello = 1
)

// Extension types that Parse reads, as listed in Hello.Extensions.
const (
	ExtensionServerName          = 0
	ExtensionSupportedGroups     = 10
	ExtensionPointFormats        = 11
	ExtensionSignatureAlgorithms = 13
	ExtensionALPN                = 16
	ExtensionSupportedVersions   = 43
	ExtensionECH                 = 0xfe0d
)

// Parse parses data, the first bytes of a TLS connection, as a ClientHello,
// which may span several handshake records. Bytes after the ClientHello are
// ignored. It returns io.ErrUnexpectedEOF while data is the start of a
// ClientHello, and ErrInvalid when data is not one.
//
// Each call parses data from the start; a Scanner continues where it
// stopped.
func Parse(data []byte) (*Hello, error) {
	var s Scanner
	return s.Scan(data)
}

// Scanner parses a ClientHello as its bytes arrive. It reassembles the first
// handshake message from one or more handshake records; each call continues
// where the previous one stopped and complete records are consumed once, so
// a hello split into many small records costs time proportional to its
// size. The zero value is ready to use.
type Scanner struct {
	off  int    // start of the first record not consumed yet
	msg  []byte // handshake bytes of the consumed records
	need int    // input length at which an incomplete result can change
}

// Need returns the length that the data must reach before Scan can make
// progress after it returned io.ErrUnexpectedEOF.
func (s *Scanner) Need() int { return s.need }

// Scan parses data, the bytes received so far: each call passes the data of
// the previous one followed by the bytes that arrived since. It returns the
// hello, io.ErrUnexpectedEOF while data is the start of one, or ErrInvalid.
func (s *Scanner) Scan(data []byte) (*Hello, error) {
	for {
		rest := data[s.off:]
		if len(rest) < recordHeaderLen {
			if !validRecordHeaderPrefix(rest) {
				return nil, ErrInvalid
			}
			// The first three header bytes are checked one by one, the
			// length once both of its bytes arrived.
			if len(rest) < 3 {
				s.need = len(data) + 1
			} else {
				s.need = s.off + recordHeaderLen
			}
			return nil, io.ErrUnexpectedEOF
		}
		if !validRecordHeaderPrefix(rest[:3]) {
			return nil, ErrInvalid
		}
		n := int(rest[3])<<8 | int(rest[4])
		if n == 0 || n > maxRecordPlaintext {
			return nil, ErrInvalid
		}
		frag := rest[recordHeaderLen:min(len(rest), recordHeaderLen+n)]
		// The message so far is s.msg followed by frag.
		at := func(i int) byte {
			if i < len(s.msg) {
				return s.msg[i]
			}
			return frag[i-len(s.msg)]
		}
		total := len(s.msg) + len(frag)
		if total > 0 && at(0) != handshakeTypeClientHello {
			return nil, ErrInvalid
		}
		want := handshakeHeaderLen
		if total >= handshakeHeaderLen {
			want += int(at(1))<<16 | int(at(2))<<8 | int(at(3))
			if total >= want {
				if len(s.msg) == 0 {
					return parseBody(frag[handshakeHeaderLen:want])
				}
				s.msg = append(s.msg, frag[:want-len(s.msg)]...)
				return parseBody(s.msg[handshakeHeaderLen:want])
			}
		}
		if len(rest) < recordHeaderLen+n {
			// The record is incomplete. The message type is checked on its
			// first byte; after that, progress needs the message bytes still
			// lacking or the end of the record, whichever comes first.
			if total == 0 {
				s.need = s.off + recordHeaderLen + 1
			} else {
				s.need = s.off + recordHeaderLen + min(n, want-len(s.msg))
			}
			return nil, io.ErrUnexpectedEOF
		}
		s.msg = append(s.msg, frag...)
		s.off += recordHeaderLen + n
	}
}

// validRecordHeaderPrefix checks up to the first three bytes of a record
// header: a handshake record with a 3.x version no newer than TLS 1.3.
func validRecordHeaderPrefix(b []byte) bool {
	switch {
	case len(b) > 0 && b[0] != recordTypeHandshake:
		return false
	case len(b) > 1 && b[1] != 3:
		return false
	case len(b) > 2 && b[2] > 4:
		return false
	}
	return true
}

func parseBody(body []byte) (*Hello, error) {
	s := cursor(body)
	version, ok := s.u16()
	if !ok || !s.skip(32) {
		return nil, ErrInvalid
	}
	if sid, ok := s.u8Prefixed(); !ok || len(sid) > 32 {
		return nil, ErrInvalid
	}
	suites, ok := s.u16Prefixed()
	if !ok || len(suites) < 2 || len(suites)%2 != 0 {
		return nil, ErrInvalid
	}
	if methods, ok := s.u8Prefixed(); !ok || len(methods) < 1 {
		return nil, ErrInvalid
	}
	storage := new(helloStorage)
	hello := &storage.hello
	hello.Version = version
	var exts cursor
	if len(s) > 0 {
		if exts, ok = s.u16Prefixed(); !ok || len(s) != 0 {
			return nil, ErrInvalid
		}
	}
	var typesBuf [32]uint16
	types := typesBuf[:0]
	// Duplicates are looked for in types while it fits typesBuf, and then in
	// a set of every type, so that a hello with thousands of extensions costs
	// time in proportion to its size.
	var seen *[1 << 16 / 64]uint64
	var groups, schemes, versions cursor
	for len(exts) > 0 {
		typ, ok := exts.u16()
		if !ok {
			return nil, ErrInvalid
		}
		data, ok := exts.u16Prefixed()
		if !ok {
			return nil, ErrInvalid
		}
		if seen == nil && len(types) == len(typesBuf) {
			seen = new([1 << 16 / 64]uint64)
			for _, t := range types {
				seen[t/64] |= 1 << (t % 64)
			}
		}
		if seen != nil {
			if seen[typ/64]&(1<<(typ%64)) != 0 {
				return nil, ErrInvalid
			}
			seen[typ/64] |= 1 << (typ % 64)
		} else if slices.Contains(types, typ) {
			return nil, ErrInvalid
		}
		types = append(types, typ)
		switch typ {
		case ExtensionServerName:
			ok = parseServerName(data, hello)
		case ExtensionALPN:
			ok = parseALPN(data, hello)
		case ExtensionSupportedVersions:
			versions, ok = valueList(data, 1)
		case ExtensionSupportedGroups:
			groups, ok = valueList(data, 2)
		case ExtensionSignatureAlgorithms:
			schemes, ok = valueList(data, 2)
		case ExtensionPointFormats:
			var formats cursor
			formats, ok = data.u8Prefixed()
			ok = ok && len(data) == 0 && len(formats) > 0
			if len(formats) <= len(storage.formats) {
				hello.PointFormats = storage.formats[:copy(storage.formats[:], formats):len(formats)]
			} else {
				hello.PointFormats = slices.Clone(formats)
			}
		case ExtensionECH:
			hello.ECH = true
		}
		if !ok {
			return nil, ErrInvalid
		}
	}
	// One array holds every list of 16-bit values.
	arena := storage.values[:0]
	if n := (len(suites)+len(groups)+len(schemes)+len(versions))/2 + len(types); n > len(storage.values) {
		arena = make([]uint16, 0, n)
	}
	hello.CipherSuites = takeValues(&arena, suites)
	if len(types) > 0 {
		start := len(arena)
		arena = append(arena, types...)
		hello.Extensions = arena[start:len(arena):len(arena)]
	}
	hello.SupportedGroups = takeValues(&arena, groups)
	hello.SignatureSchemes = takeValues(&arena, schemes)
	hello.SupportedVersions = takeValues(&arena, versions)
	hello.name, hello.prepared = hostmatch.Normalize(hello.ServerName), true
	return hello, nil
}

// helloStorage allocates a Hello together with room for its lists,
// which those of common clients fit in.
type helloStorage struct {
	hello   Hello
	values  [96]uint16
	formats [4]uint8
}

// valueList reads an extension that holds a non-empty list of 16-bit values
// with a length prefix of prefixLen bytes.
func valueList(data cursor, prefixLen int) (cursor, bool) {
	var list cursor
	var ok bool
	if prefixLen == 1 {
		list, ok = data.u8Prefixed()
	} else {
		list, ok = data.u16Prefixed()
	}
	return list, ok && len(data) == 0 && len(list) > 0 && len(list)%2 == 0
}

// takeValues appends the big-endian 16-bit values of b to arena, which has
// room for them, and returns them as a slice of their own, or nil when b is
// empty.
func takeValues(arena *[]uint16, b []byte) []uint16 {
	if len(b) == 0 {
		return nil
	}
	start, end := len(*arena), len(*arena)+len(b)/2
	vs := (*arena)[start:end:end]
	for i := range vs {
		vs[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	*arena = (*arena)[:end]
	return vs
}

// parseServerName follows crypto/tls: one host_name entry, not empty and
// without a trailing dot.
func parseServerName(data cursor, hello *Hello) bool {
	list, ok := data.u16Prefixed()
	if !ok || len(data) != 0 || len(list) == 0 {
		return false
	}
	for len(list) > 0 {
		nameType, ok := list.u8()
		if !ok {
			return false
		}
		name, ok := list.u16Prefixed()
		if !ok || len(name) == 0 {
			return false
		}
		if nameType != 0 {
			continue
		}
		if hello.ServerName != "" || name[len(name)-1] == '.' {
			return false
		}
		hello.ServerName = string(name)
	}
	return true
}

func parseALPN(data cursor, hello *Hello) bool {
	list, ok := data.u16Prefixed()
	if !ok || len(data) != 0 || len(list) == 0 {
		return false
	}
	count := 0
	for l := list; len(l) > 0; count++ {
		if proto, ok := l.u8Prefixed(); !ok || len(proto) == 0 {
			return false
		}
	}
	hello.ALPN = make([]string, 0, count)
	for len(list) > 0 {
		proto, _ := list.u8Prefixed()
		hello.ALPN = append(hello.ALPN, alpnString(proto))
	}
	return true
}

// alpnString converts a protocol ID, sharing the strings of common ones.
func alpnString(b []byte) string {
	switch string(b) {
	case "h2":
		return "h2"
	case "http/1.1":
		return "http/1.1"
	case "http/1.0":
		return "http/1.0"
	case "h3":
		return "h3"
	case "acme-tls/1":
		return "acme-tls/1"
	}
	return string(b)
}

// cursor reads big-endian fields from the front of a byte slice.
type cursor []byte

func (c *cursor) skip(n int) bool {
	if len(*c) < n {
		return false
	}
	*c = (*c)[n:]
	return true
}

func (c *cursor) u8() (byte, bool) {
	if len(*c) < 1 {
		return 0, false
	}
	v := (*c)[0]
	*c = (*c)[1:]
	return v, true
}

func (c *cursor) u16() (uint16, bool) {
	if len(*c) < 2 {
		return 0, false
	}
	v := uint16((*c)[0])<<8 | uint16((*c)[1])
	*c = (*c)[2:]
	return v, true
}

func (c *cursor) bytes(n int) (cursor, bool) {
	if len(*c) < n {
		return nil, false
	}
	v := (*c)[:n:n]
	*c = (*c)[n:]
	return v, true
}

func (c *cursor) u8Prefixed() (cursor, bool) {
	n, ok := c.u8()
	if !ok {
		return nil, false
	}
	return c.bytes(int(n))
}

func (c *cursor) u16Prefixed() (cursor, bool) {
	n, ok := c.u16()
	if !ok {
		return nil, false
	}
	return c.bytes(int(n))
}
