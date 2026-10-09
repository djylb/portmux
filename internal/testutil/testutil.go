// Package testutil builds and captures the protocol bytes that the tests of
// portmux and its packages feed to parsers. Only tests import it.
package testutil

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"testing"
	"time"
)

// HelloRecord builds a ClientHello record around the extensions block, or
// without one when exts is nil.
func HelloRecord(exts []byte) []byte {
	return HelloRecordWith(tls.VersionTLS12, []uint16{tls.TLS_AES_128_GCM_SHA256}, exts)
}

// HelloRecordWith builds a ClientHello record with the given legacy version
// and cipher suites.
func HelloRecordWith(version uint16, suites []uint16, exts []byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // session id
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(suites)))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0) // compression methods
	if exts != nil {
		body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
		body = append(body, exts...)
	}
	msg := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	msg = append(msg, body...)
	rec := []byte{22, 3, 1}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(msg)))
	return append(rec, msg...)
}

// Ext builds an extension.
func Ext(typ uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// U16List joins items behind a 16-bit length.
func U16List(items ...[]byte) []byte {
	var list []byte
	for _, it := range items {
		list = append(list, it...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

// SNIEntry builds a server_name entry.
func SNIEntry(nameType byte, name string) []byte {
	b := binary.BigEndian.AppendUint16([]byte{nameType}, uint16(len(name)))
	return append(b, name...)
}

// SNIHello builds a ClientHello record with the server name.
func SNIHello(name string) []byte {
	return HelloRecord(Ext(0, U16List(SNIEntry(0, name))))
}

// Values16 encodes 16-bit values.
func Values16(vs ...uint16) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

// ClientHelloBytes captures the ClientHello that crypto/tls sends for cfg.
func ClientHelloBytes(tb testing.TB, cfg *tls.Config) []byte {
	tb.Helper()
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		_ = tls.Client(c1, cfg).Handshake()
		_ = c1.Close()
	}()
	return capture(tb, c2, func(b []byte) bool {
		// The handshake message is complete once the records hold its length.
		var msg []byte
		for len(b) >= 5 {
			n := int(binary.BigEndian.Uint16(b[3:]))
			if len(b) < 5+n {
				break
			}
			msg, b = append(msg, b[5:5+n]...), b[5+n:]
		}
		return len(msg) >= 4 && len(msg) >= 4+(int(msg[1])<<16|int(msg[2])<<8|int(msg[3]))
	})
}

// H2CBytes captures the first bytes that the standard library's h2c client
// sends for req, up to the end of the request's header block.
func H2CBytes(tb testing.TB, req *http.Request) []byte {
	tb.Helper()
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: &protocols, DialContext: func(context.Context, string, string) (net.Conn, error) { return c1, nil }}
	defer tr.CloseIdleConnections()
	go func() { _, _ = tr.RoundTrip(req) }()
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	return capture(tb, c2, func(b []byte) bool {
		if len(b) < len(preface) {
			return false
		}
		for b = b[len(preface):]; len(b) >= 9; {
			n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
			if len(b) < 9+n {
				return false
			}
			if (b[3] == 1 || b[3] == 9) && b[4]&4 != 0 { // HEADERS or CONTINUATION with END_HEADERS
				return true
			}
			b = b[9+n:]
		}
		return false
	})
}

func capture(tb testing.TB, c net.Conn, done func([]byte) bool) []byte {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if done(buf) {
			return buf
		}
		if err != nil {
			tb.Fatalf("capture: %v", err)
		}
	}
}

// JA4Example builds the ClientHello of the worked example of the JA4
// specification, whose fingerprint is t13d1516h2_8daaf6152771_e5627efa2ab1,
// with GREASE values added that JA4 leaves out.
func JA4Example() []byte {
	suites := []uint16{0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	schemes := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	data := map[uint16][]byte{
		0x0000: U16List(SNIEntry(0, "www.example.com")),
		0x0010: U16List([]byte("\x02h2"), []byte("\x08http/1.1")),
		0x000d: U16List(Values16(schemes...)),
		0x002b: append([]byte{6}, Values16(0x5a5a, tls.VersionTLS13, tls.VersionTLS12)...),
		0x000a: U16List(Values16(0x4a4a, 0x001d, 0x0017, 0x0018)),
		0x000b: {1, 0},
	}
	var exts []byte
	for _, typ := range []uint16{0x0a0a, 0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015, 0x1a1a} {
		exts = append(exts, Ext(typ, data[typ])...)
	}
	return HelloRecordWith(tls.VersionTLS12, suites, exts)
}
