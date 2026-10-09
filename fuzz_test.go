package portmux

import (
	"testing"
)

// checkFinal verifies the Matcher contract for a parser: a decision made on a
// prefix of data never changes for data itself.
func checkFinal(t *testing.T, data []byte, parse func([]byte) Result) {
	full := parse(data)
	for i := range len(data) {
		if res := parse(data[:i]); res != NeedMore && res != full {
			t.Fatalf("prefix of %d bytes decided %v, full input %v", i, res, full)
		}
	}
}

// FuzzProtocolMatchers checks that the protocol matchers decide finally and
// never panic.
func FuzzProtocolMatchers(f *testing.F) {
	f.Add(pgMessage(3<<16, "user\x00a\x00\x00"))
	f.Add([]byte("\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test"))
	f.Add([]byte("\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00"))
	f.Add([]byte{0, 14, openVPNResetV2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0})
	f.Add([]byte{5, 2, 0, 2})
	f.Add([]byte{4, 1, 0, 80, 0, 0, 0, 1, 'u', 0, 'h', 0})
	f.Add([]byte("<?xml version='1.0'?><stream:stream xmlns='jabber:client'>"))
	f.Add([]byte("\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"))
	matchers := []Matcher{PostgreSQL(), MQTT(), RDP(), OpenVPN(), SOCKS4(), SOCKS5(), SSH(), HTTP2Preface(), XMPP(), DNS()}
	f.Fuzz(func(t *testing.T, data []byte) {
		checkFinal(t, data, func(b []byte) Result {
			_, res := rdpCookie(b)
			return res
		})
		for _, m := range matchers {
			checkFinal(t, data, func(b []byte) Result {
				in := NewInput(nil, nil)
				in.SetBytes(b, false)
				return m.Match(in)
			})
		}
	})
}
