package portmux

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"unicode/utf8"
)

// SOCKS5 matches SOCKS5 clients by their greeting: version 5 and a non-empty
// list of authentication methods. It decides as soon as the greeting is
// complete, since the client then waits for the server.
func SOCKS5() Matcher {
	return binaryMatcher{name: "SOCKS5", match: matchSOCKS5}
}

func matchSOCKS5(b []byte) Result {
	switch {
	case len(b) == 0:
		return NeedMore
	case b[0] != 5:
		return NoMatch
	case len(b) < 2:
		return NeedMore
	case b[1] == 0:
		return NoMatch
	case len(b) < 2+int(b[1]):
		return NeedMore
	}
	return Match
}

// maxSOCKS4Field bounds the user ID and the SOCKS4a host name.
const maxSOCKS4Field = 255

// SOCKS4 matches SOCKS4 and SOCKS4a CONNECT and BIND requests. It decides once
// the request, including its user ID and SOCKS4a host name, is complete.
func SOCKS4() Matcher {
	return binaryMatcher{name: "SOCKS4", match: matchSOCKS4}
}

func matchSOCKS4(b []byte) Result {
	switch {
	case len(b) == 0:
		return NeedMore
	case b[0] != 4:
		return NoMatch
	case len(b) < 2:
		return NeedMore
	case b[1] != 1 && b[1] != 2:
		return NoMatch
	case len(b) < 8:
		return NeedMore
	}
	rest, res := cutNulField(b[8:])
	if res != Match {
		return res
	}
	// SOCKS4a: an address of 0.0.0.x with x != 0 is followed by a host name.
	if b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] != 0 {
		if len(rest) > 0 && rest[0] == 0 {
			return NoMatch
		}
		if _, res = cutNulField(rest); res != Match {
			return res
		}
	}
	return Match
}

// cutNulField splits a NUL-terminated field of at most maxSOCKS4Field bytes
// from the front of b.
func cutNulField(b []byte) ([]byte, Result) {
	i := bytes.IndexByte(b[:min(len(b), maxSOCKS4Field+1)], 0)
	switch {
	case i >= 0:
		return b[i+1:], Match
	case len(b) > maxSOCKS4Field:
		return nil, NoMatch
	}
	return nil, NeedMore
}

// PostgreSQL matches PostgreSQL clients by their first message: an SSL or
// GSSAPI encryption request, a cancel request, or a startup message of
// protocol version 3. It decides after eight bytes. Clients that ask for
// encryption send their startup message only after the server's answer.
func PostgreSQL() Matcher {
	return binaryMatcher{name: "PostgreSQL", match: matchPostgreSQL}
}

const (
	pgCancelRequest  = 80877102
	pgSSLRequest     = 80877103
	pgGSSENCRequest  = 80877104
	pgMaxStartupSize = 10000 // as the server enforces
)

func matchPostgreSQL(b []byte) Result {
	// The length is below 2^16, so its first two bytes are zero.
	for i := range min(len(b), 2) {
		if b[i] != 0 {
			return NoMatch
		}
	}
	if len(b) < 8 {
		return NeedMore
	}
	n, code := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])
	switch {
	case code == pgSSLRequest || code == pgGSSENCRequest:
		return matchIf(n == 8)
	case code == pgCancelRequest:
		// The secret key takes 4 bytes, or up to 256 since protocol 3.2.
		return matchIf(n >= 16 && n <= 12+256)
	case code>>16 == 3:
		return matchIf(n > 8 && n <= pgMaxStartupSize)
	}
	return NoMatch
}

// MQTT matches MQTT clients by their CONNECT packet, for protocol versions
// 3.1, 3.1.1 and 5. It decides once the protocol name and level arrived.
func MQTT() Matcher {
	return binaryMatcher{name: "MQTT", match: matchMQTT}
}

var mqttProtocols = []string{"\x00\x04MQTT\x04", "\x00\x04MQTT\x05", "\x00\x06MQIsdp\x03"}

func matchMQTT(b []byte) Result {
	switch {
	case len(b) == 0:
		return NeedMore
	case b[0] != 0x10: // CONNECT without flags
		return NoMatch
	}
	// The remaining length takes one to four bytes, seven bits each.
	i := 1
	for ; i < len(b) && b[i]&0x80 != 0; i++ {
		if i == 4 {
			return NoMatch
		}
	}
	if i >= len(b) {
		return NeedMore
	}
	length := 0
	for j := 1; j <= i; j++ {
		length |= int(b[j]&127) << (7 * (j - 1))
	}
	payload := b[i+1:]
	res := matchPrefixes(payload[:min(len(payload), length)], mqttProtocols)
	if res == NeedMore && (length < 7 || len(payload) >= length) {
		return NoMatch
	}
	return res
}

// RDP matches Remote Desktop clients by the X.224 connection request that
// opens the connection. It decides after six bytes.
func RDP() Matcher {
	return binaryMatcher{name: "RDP", match: matchRDP}
}

func matchRDP(b []byte) Result {
	// A TPKT header of version 3, then the request, whose length indicator
	// covers the rest of the packet.
	if res := matchPrefixes(b, []string{"\x03\x00"}); res != Match {
		return res
	}
	if len(b) < 6 {
		return NeedMore
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	return matchIf(n >= 11 && int(b[4]) == n-5 && b[5] == 0xe0)
}

// OpenVPN matches OpenVPN clients over TCP by the hard reset packet that
// opens a session, of version 2 or 3 (tls-crypt-v2). It decides after three
// bytes.
func OpenVPN() Matcher {
	return binaryMatcher{name: "OpenVPN", match: matchOpenVPN}
}

const (
	openVPNResetV2 = 7 << 3 // P_CONTROL_HARD_RESET_CLIENT_V2, key ID 0
	openVPNResetV3 = 10 << 3
	openVPNMinSize = 14 // opcode, session ID, empty ACK array, packet ID
	openVPNMaxSize = 4096
)

func matchOpenVPN(b []byte) Result {
	if len(b) > 0 && b[0] > openVPNMaxSize>>8 {
		return NoMatch
	}
	if len(b) < 3 {
		return NeedMore
	}
	n := int(binary.BigEndian.Uint16(b))
	return matchIf(n >= openVPNMinSize && n <= openVPNMaxSize && (b[2] == openVPNResetV2 || b[2] == openVPNResetV3))
}

// binaryMatcher matches a protocol by a function of the first bytes.
type binaryMatcher struct {
	name  string
	match func([]byte) Result
}

func (m binaryMatcher) Match(in *Input) Result { return m.match(in.data) }
func (m binaryMatcher) String() string         { return m.name + "()" }

func matchIf(ok bool) Result {
	if ok {
		return Match
	}
	return NoMatch
}

// XMPP matches XMPP clients and servers by the stream header they open with,
// an optional XML declaration and a stream:stream element in the jabber:client
// or jabber:server namespace, or that of a component. It decides once the
// stream element is complete. It requires both the stream prefix binding
// and the default content namespace, and rules out headers longer than 2 KiB.
func XMPP() Matcher {
	return binaryMatcher{name: "XMPP", match: matchXMPP}
}

// maxXMPPHeader bounds the declaration and stream element that XMPP looks at,
// so that a header sent a byte at a time is not scanned again at length on
// every read.
const maxXMPPHeader = 2 << 10

const xmlns = "xmlns"

func matchXMPP(b []byte) Result {
	res := matchXMPPHeader(b[:min(len(b), maxXMPPHeader)])
	if res == NeedMore && len(b) >= maxXMPPHeader {
		return NoMatch
	}
	return res
}

func matchXMPPHeader(b []byte) Result {
	const decl, stream = "<?xml", "<stream:stream"
	switch {
	case len(b) == 0:
		return NeedMore
	case b[0] != '<':
		return NoMatch
	}
	rest := b
	if res := matchPrefixes(b, []string{decl, stream}); res != Match {
		return res
	}
	if bytes.HasPrefix(b, []byte(decl)) {
		_, after, ok := bytes.Cut(b, []byte("?>"))
		if !ok {
			return NeedMore
		}
		if !xmppDeclaration.Match(b[:len(b)-len(after)]) {
			return NoMatch
		}
		rest = bytes.TrimLeft(after, " \t\r\n")
		if res := matchPrefixes(rest, []string{stream}); res != Match {
			return res
		}
	}
	var quote byte
	for i, c := range rest {
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '>':
			return matchIf(xmppAttributes(rest[len(stream):i]))
		}
	}
	return NeedMore
}

// XML declarations in XMPP use XML 1.0 and UTF-8.
var xmppDeclaration = regexp.MustCompile(`^<\?xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*('1\.0'|"1\.0")([ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*(?i:'UTF-8'|"UTF-8"))?([ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*('yes'|'no'|"yes"|"no"))?[ \t\r\n]*\?>$`)

// streamAttrs scans one bounded start tag. A nil name marks the end.
type streamAttrs []byte

func (a *streamAttrs) next() (name, value []byte, valid bool) {
	const space = " \t\r\n"
	rest := bytes.TrimLeft(*a, space)
	if len(rest) == 0 {
		return nil, nil, true
	}
	if len(rest) == len(*a) {
		return nil, nil, false
	}
	i := bytes.IndexAny(rest, "="+space)
	if i < 1 {
		return nil, nil, false
	}
	name = rest[:i]
	rest = bytes.TrimLeft(rest[i:], space)
	if len(rest) == 0 || rest[0] != '=' {
		return nil, nil, false
	}
	rest = bytes.TrimLeft(rest[1:], space)
	if len(rest) == 0 || rest[0] != '\'' && rest[0] != '"' {
		return nil, nil, false
	}
	end := bytes.IndexByte(rest[1:], rest[0])
	if end < 0 {
		return nil, nil, false
	}
	*a = rest[2+end:]
	return name, rest[1 : 1+end], true
}

const (
	xmlNS    = "http://www.w3.org/XML/1998/namespace"
	xmlnsNS  = "http://www.w3.org/2000/xmlns/"
	streamNS = "http://etherx.jabber.org/streams"
)

func xmppAttributes(header []byte) bool {
	var namespace, stream bool
	var seen uint64
	for attrs := streamAttrs(header); ; {
		prior := streamAttrs(header[:len(header)-len(attrs)])
		name, value, ok := attrs.next()
		if !ok || name == nil {
			return ok && namespace && stream
		}
		prefix, local := xmlParts(name)
		if !xmlName(local) || len(prefix) > 0 && !xmlName(prefix) || !validXMLValue(value) {
			return false
		}
		uri := xmlAttrNS(prefix, header)
		if len(prefix) > 0 && len(uri) == 0 {
			return false
		}

		// Only a repeated bit needs the exact expanded-name check.
		bit := uint64(1) << ((int(local[0]) + len(local)) % 64)
		if seen&bit != 0 && prior.contains(local, uri, header) {
			return false
		}
		seen |= bit
		switch {
		case string(name) == xmlns:
			switch {
			case xmlValueEqual(value, []byte("jabber:client")), xmlValueEqual(value, []byte("jabber:server")),
				xmlValueEqual(value, []byte("jabber:component:accept")), xmlValueEqual(value, []byte("jabber:component:connect")):
				namespace = true
			default:
				return false
			}
		case string(name) == "xmlns:stream":
			stream = xmlValueEqual(value, []byte(streamNS))
		case string(prefix) == xmlns:
			if len(value) == 0 || string(local) == xmlns || (string(local) == "xml") != xmlValueEqual(value, []byte(xmlNS)) || xmlValueEqual(value, []byte(xmlnsNS)) {
				return false
			}
		}
	}
}

func xmlParts(name []byte) (prefix, local []byte) {
	prefix, local, ok := bytes.Cut(name, []byte(":"))
	if !ok {
		return nil, name
	}
	if len(prefix) == 0 {
		return nil, nil
	}
	return prefix, local
}

func (a *streamAttrs) contains(local, uri, header []byte) bool {
	for {
		name, _, ok := a.next()
		if !ok || name == nil {
			return false
		}
		p, l := xmlParts(name)
		if bytes.Equal(local, l) && xmlValueEqual(uri, xmlAttrNS(p, header)) {
			return true
		}
	}
}

var xmlNamespace, xmlnsNamespace = []byte(xmlNS), []byte(xmlnsNS)

func xmlAttrNS(prefix, header []byte) []byte {
	switch string(prefix) {
	case "":
		return nil
	case "xml":
		return xmlNamespace
	case xmlns:
		return xmlnsNamespace
	}
	for a := streamAttrs(header); ; {
		name, value, ok := a.next()
		if !ok || name == nil {
			return nil
		}
		p, l := xmlParts(name)
		if string(p) == xmlns && bytes.Equal(l, prefix) {
			return value
		}
	}
}

// xmlName checks a namespace-free XML 1.0 name (NameStartChar / NameChar).
func xmlName(name []byte) bool {
	for i := 0; i < len(name); {
		r, n := utf8.DecodeRune(name[i:])
		extra := i > 0 && (r == '-' || r == '.' || r >= '0' && r <= '9' || r == 0xb7 || r >= 0x300 && r <= 0x36f || r >= 0x203f && r <= 0x2040)
		if r == utf8.RuneError && n == 1 || !xmlNameStart(r) && !extra {
			return false
		}
		i += n
	}
	return len(name) > 0
}

func xmlNameStart(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r == '_' ||
		r >= 0xc0 && r <= 0xd6 || r >= 0xd8 && r <= 0xf6 || r >= 0xf8 && r <= 0x2ff ||
		r >= 0x370 && r <= 0x37d || r >= 0x37f && r <= 0x1fff || r >= 0x200c && r <= 0x200d ||
		r >= 0x2070 && r <= 0x218f || r >= 0x2c00 && r <= 0x2fef || r >= 0x3001 && r <= 0xd7ff ||
		r >= 0xf900 && r <= 0xfdcf || r >= 0xfdf0 && r <= 0xfffd || r >= 0x10000 && r <= 0xeffff
}

func validXMLValue(b []byte) bool {
	for len(b) > 0 {
		r, n := xmlValueRune(b)
		if n == 0 || !xmlCharacter(r) {
			return false
		}
		b = b[n:]
	}
	return true
}

func xmlValueEqual(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	for len(a) > 0 && len(b) > 0 {
		ra, na := xmlValueRune(a)
		rb, nb := xmlValueRune(b)
		if na == 0 || nb == 0 || ra != rb {
			return false
		}
		a, b = a[na:], b[nb:]
	}
	return len(a) == 0 && len(b) == 0
}

// xmlValueRune decodes one character with XML attribute normalization.
func xmlValueRune(b []byte) (rune, int) {
	switch b[0] {
	case '<':
		return 0, 0
	case '\r':
		if len(b) > 1 && b[1] == '\n' {
			return ' ', 2
		}
		return ' ', 1
	case '\n', '\t':
		return ' ', 1
	case '&':
		ref, _, ok := bytes.Cut(b[1:], []byte(";"))
		if !ok {
			return 0, 0
		}
		n := len(ref) + 2
		switch string(ref) {
		case "amp":
			return '&', n
		case "lt":
			return '<', n
		case "gt":
			return '>', n
		case "apos":
			return '\'', n
		case "quot":
			return '"', n
		}
		if len(ref) < 2 || ref[0] != '#' {
			return 0, 0
		}
		base := rune(10)
		ref = ref[1:]
		if ref[0] == 'x' {
			base, ref = 16, ref[1:]
		}
		if len(ref) == 0 {
			return 0, 0
		}
		var value rune
		for _, c := range ref {
			var digit rune
			switch {
			case c >= '0' && c <= '9':
				digit = rune(c - '0')
			case base == 16 && c|32 >= 'a' && c|32 <= 'f':
				digit = rune((c|32)-'a') + 10
			default:
				return 0, 0
			}
			value = value*base + digit
			if value > utf8.MaxRune {
				return 0, 0
			}
		}
		return value, n
	default:
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n == 1 {
			return 0, 0
		}
		return r, n
	}
}

func xmlCharacter(r rune) bool {
	return r == '\t' || r == '\n' || r == '\r' || r >= ' ' && r <= 0xd7ff ||
		r >= 0xe000 && r <= 0xfffd || r >= 0x10000 && r <= utf8.MaxRune
}

// DNS matches DNS queries over TCP by their length prefix and header: a
// standard query with one question and no answers. It matches after the
// fourteen bytes of the length and the header, and rules other protocols out
// at their first byte that a query does not have, so that short messages of
// clients that then wait, such as a PostgreSQL SSL request, are not held
// back.
func DNS() Matcher {
	return binaryMatcher{name: "DNS", match: matchDNS}
}

func matchDNS(b []byte) Result {
	// A message of at least 17 bytes, a query (QR clear) with opcode QUERY, a
	// reserved Z bit clear and no response code, as clients send, with one
	// question and no answer or authority records.
	if len(b) >= 2 && binary.BigEndian.Uint16(b) < 17 ||
		len(b) >= 5 && b[4]&0xf8 != 0 ||
		len(b) >= 6 && b[5]&0x4f != 0 {
		return NoMatch
	}
	for i, want := range [...]byte{0, 1, 0, 0, 0, 0} {
		if 6+i < len(b) && b[6+i] != want {
			return NoMatch
		}
	}
	if len(b) < 14 {
		return NeedMore
	}
	return Match
}

func rdpCookie(data []byte) (string, Result) {
	if res := matchRDP(data); res != Match {
		return "", res
	}
	n := int(binary.BigEndian.Uint16(data[2:]))
	if len(data) < n {
		return "", NeedMore
	}
	// The cookie follows the fixed part of the request, which is 7 bytes
	// after the 4-byte TPKT header, and ends with CRLF.
	rest := data[11:n]
	const prefix = "Cookie: "
	if !bytes.HasPrefix(rest, []byte(prefix)) {
		return "", NoMatch
	}
	line, _, ok := bytes.Cut(rest[len(prefix):], []byte("\r\n"))
	if !ok {
		return "", NoMatch
	}
	_, value, ok := bytes.Cut(line, []byte("="))
	if !ok {
		return "", NoMatch
	}
	return string(value), Match
}
