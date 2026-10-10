package portmux

import (
	"bytes"
	"encoding/binary"
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
		return matchIf(n == 16)
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
	return matchPrefixes(b[i+1:], mqttProtocols)
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
// stream element is complete.
func XMPP() Matcher {
	return binaryMatcher{name: "XMPP", match: matchXMPP}
}

func matchXMPP(b []byte) Result {
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
		rest = bytes.TrimLeft(after, " \t\r\n")
		if res := matchPrefixes(rest, []string{stream}); res != Match {
			return res
		}
	}
	end := bytes.IndexByte(rest, '>')
	if end < 0 {
		return NeedMore
	}
	return matchIf(bytes.Contains(rest[:end], []byte("jabber:")))
}

// DNS matches DNS queries over TCP by their length prefix and header: a
// standard query with one question and no answers. It decides after the
// fourteen bytes of the length and the header.
func DNS() Matcher {
	return binaryMatcher{name: "DNS", match: matchDNS}
}

func matchDNS(b []byte) Result {
	if len(b) < 14 {
		return NeedMore
	}
	n := binary.BigEndian.Uint16(b)
	flags := binary.BigEndian.Uint16(b[4:])
	qd, an, ns := binary.BigEndian.Uint16(b[6:]), binary.BigEndian.Uint16(b[8:]), binary.BigEndian.Uint16(b[10:])
	// A query (QR clear) with opcode QUERY, a reserved Z bit clear and no
	// response code, as clients send.
	return matchIf(n >= 17 && flags&0xf840 == 0 && flags&0x000f == 0 && qd == 1 && an == 0 && ns == 0)
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
