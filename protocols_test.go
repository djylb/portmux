package portmux

import (
	"encoding/binary"
	"regexp"
	"strings"
	"testing"
)

// matchAll runs m on every prefix of data and checks that it waits until it
// has seen decideAt bytes and then gives want.
func matchAll(t *testing.T, m Matcher, data []byte, decideAt int, want Result) {
	t.Helper()
	in := NewInput(nil, nil)
	for i := range len(data) + 1 {
		in.SetBytes(data[:i], false)
		got := m.Match(in)
		switch {
		case i < decideAt && got != NeedMore:
			t.Fatalf("%s on %q: %v after %d bytes, want NeedMore", describe(m), data, got, i)
		case i >= decideAt && got != want:
			t.Fatalf("%s on %q: %v after %d bytes, want %v", describe(m), data, got, i, want)
		}
	}
}

func pgMessage(code uint32, rest string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(8+len(rest)))
	b = binary.BigEndian.AppendUint32(b, code)
	return append(b, rest...)
}

func TestPostgreSQL(t *testing.T) {
	m := PostgreSQL()
	matchAll(t, m, pgMessage(pgSSLRequest, ""), 8, Match)
	matchAll(t, m, pgMessage(pgGSSENCRequest, ""), 8, Match)
	matchAll(t, m, pgMessage(pgCancelRequest, "\x00\x00\x00\x01\x00\x00\x00\x02"), 8, Match)
	pid := "\x00\x00\x00\x01"
	matchAll(t, m, pgMessage(pgCancelRequest, pid+string(make([]byte, 32))), 8, Match) // protocol 3.2 key
	matchAll(t, m, pgMessage(pgCancelRequest, pid+string(make([]byte, 257))), 8, NoMatch)
	matchAll(t, m, pgMessage(3<<16, "user\x00postgres\x00\x00"), 8, Match)
	matchAll(t, m, pgMessage(3<<16|2, "user\x00postgres\x00\x00"), 8, Match) // protocol 3.2

	bad := pgMessage(pgSSLRequest, "x") // wrong length
	matchAll(t, m, bad, 8, NoMatch)
	matchAll(t, m, pgMessage(2<<16, "user\x00a\x00\x00"), 8, NoMatch) // protocol 2
	matchAll(t, m, pgMessage(3<<16, ""), 8, NoMatch)                  // empty startup
	matchAll(t, m, []byte("GET / HTTP/1.1\r\n"), 1, NoMatch)
	matchAll(t, m, []byte{0, 1}, 2, NoMatch)
}

func TestMQTT(t *testing.T) {
	m := MQTT()
	v311 := []byte("\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test")
	matchAll(t, m, v311, 9, Match)
	v5 := []byte("\x10\x11\x00\x04MQTT\x05\x02\x00\x3c\x00\x00\x04test")
	matchAll(t, m, v5, 9, Match)
	v31 := []byte("\x10\x12\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x04test")
	matchAll(t, m, v31, 11, Match)
	// A remaining length of 200 takes two bytes.
	long := append([]byte("\x10\xc8\x01\x00\x04MQTT\x04"), make([]byte, 190)...)
	matchAll(t, m, long, 10, Match)

	matchAll(t, m, []byte("\x10\x10\x00\x04MQTT\x06"), 9, NoMatch) // unknown level
	matchAll(t, m, []byte("\x12\x10"), 1, NoMatch)                 // flags set
	matchAll(t, m, []byte("\x10\xff\xff\xff\xff\x01"), 5, NoMatch) // length too long
	matchAll(t, m, []byte("\x10\x10\x00\x04MQTX"), 8, NoMatch)
}

func TestRDP(t *testing.T) {
	m := RDP()
	cookie := "Cookie: mstshash=user\r\n"
	neg := "\x01\x00\x08\x00\x03\x00\x00\x00"
	x224 := "\xe0\x00\x00\x00\x00\x00" + cookie + neg
	n := 4 + 1 + len(x224)
	req := binary.BigEndian.AppendUint16([]byte{3, 0}, uint16(n))
	req = append(append(req, byte(n-5)), x224...)
	matchAll(t, m, req, 6, Match)

	wrongLength := append([]byte(nil), req...)
	wrongLength[4]++
	matchAll(t, m, wrongLength, 6, NoMatch)
	confirm := append([]byte(nil), req...)
	confirm[5] = 0xd0 // a connection confirm comes from servers
	matchAll(t, m, confirm, 6, NoMatch)
	matchAll(t, m, []byte{3, 1}, 2, NoMatch)
	matchAll(t, m, []byte{0x16, 3}, 1, NoMatch)
}

func TestOpenVPN(t *testing.T) {
	m := OpenVPN()
	reset := []byte{0, 14, openVPNResetV2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0}
	matchAll(t, m, reset, 3, Match)
	v3 := append([]byte{1, 0x2a, openVPNResetV3}, make([]byte, 0x12a-1)...)
	matchAll(t, m, v3, 3, Match)

	matchAll(t, m, []byte{0, 14, 0x20}, 3, NoMatch) // a data packet
	matchAll(t, m, []byte{0, 10, openVPNResetV2}, 3, NoMatch)
	matchAll(t, m, []byte("GET"), 1, NoMatch)
}

func TestRegexp(t *testing.T) {
	m := Regexp(regexp.MustCompile(`^[A-Z]+ \S+ RTSP/1\.0`), 16)
	matchAll(t, m, []byte("OPTIONS * RTSP/1.0\r\n"), 16, NoMatch) // only 16 bytes are seen
	m = Regexp(regexp.MustCompile(`^[A-Z]+ \S+ RTSP/1\.0`), 18)
	matchAll(t, m, []byte("OPTIONS * RTSP/1.0\r\n"), 18, Match)
	matchAll(t, m, []byte("OPTIONS * HTTP/1.1\r\n"), 18, NoMatch)

	// Final input decides with fewer bytes.
	in := NewInput(nil, nil)
	in.SetBytes([]byte("OPTIONS * RTSP/1.0"), true)
	if Regexp(regexp.MustCompile(`RTSP`), 100).Match(in) != Match {
		t.Fatal("final input")
	}
	if got := describe(m); got != `Regexp("^[A-Z]+ \\S+ RTSP/1\\.0", 18)` {
		t.Fatalf("description %s", got)
	}
	for _, m := range []Matcher{PostgreSQL(), MQTT(), RDP(), OpenVPN(), SOCKS4(), SOCKS5()} {
		if s := describe(m); s[len(s)-2:] != "()" {
			t.Fatalf("description %s", s)
		}
	}
}

//goland:noinspection HttpUrlsUsage
func TestXMPP(t *testing.T) {
	m := XMPP()
	client := "<?xml version='1.0'?><stream:stream to='example.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
	matchAll(t, m, []byte(client), len(client), Match)
	direct := "<stream:stream xmlns=\"jabber:server\" to=\"example.com\">"
	matchAll(t, m, []byte(direct), len(direct), Match)
	other := "<?xml version='1.0'?>\n<stream:stream xmlns='urn:other'>"
	matchAll(t, m, []byte(other), len(other), NoMatch)
	matchAll(t, m, []byte("<?xml version='1.0'?><html>"), len("<?xml version='1.0'?><h"), NoMatch)
	matchAll(t, m, []byte("<html>"), 2, NoMatch)
	long := "<stream:stream xmlns='jabber:client' to='" + strings.Repeat("a", maxXMPPHeader) + "'>"
	matchAll(t, m, []byte(long), maxXMPPHeader, NoMatch)
	matchAll(t, m, []byte("GET"), 1, NoMatch)
}

func TestDNS(t *testing.T) {
	m := DNS()
	// A query for example.com A with the AD bit, as dig sends it.
	q := []byte("\x00\x1d\x12\x34\x00\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
	matchAll(t, m, q, 14, Match)
	// Other messages are ruled out at their first byte that differs.
	response := append([]byte(nil), q...)
	response[4] |= 0x80
	matchAll(t, m, response, 5, NoMatch)
	twoQuestions := append([]byte(nil), q...)
	twoQuestions[7] = 2
	matchAll(t, m, twoQuestions, 8, NoMatch)
	answer := append([]byte(nil), q...)
	answer[9] = 1
	matchAll(t, m, answer, 10, NoMatch)
	matchAll(t, m, []byte("GET / HTTP/1.1\r\n"), 5, NoMatch)
	// A PostgreSQL SSL request, after which the client waits.
	matchAll(t, m, pgMessage(pgSSLRequest, ""), 2, NoMatch)
}

func TestRDPCookie(t *testing.T) {
	request := func(cookie string) []byte {
		x224 := "\xe0\x00\x00\x00\x00\x00" + cookie + "\x01\x00\x08\x00\x03\x00\x00\x00"
		n := 5 + len(x224)
		b := binary.BigEndian.AppendUint16([]byte{3, 0}, uint16(n))
		return append(append(b, byte(n-5)), x224...)
	}
	for cookie, want := range map[string]string{
		"Cookie: mstshash=alice\r\n":             "alice",
		"Cookie: msts=3640205228.15629.0000\r\n": "3640205228.15629.0000",
	} {
		data := request(cookie)
		if got, res := rdpCookie(data); res != Match || got != want {
			t.Errorf("%q: %q, %v", cookie, got, res)
		}
		if _, res := rdpCookie(data[:len(data)-1]); res != NeedMore {
			t.Errorf("%q cut short: %v", cookie, res)
		}
	}
	if _, res := rdpCookie(request("")); res != NoMatch {
		t.Errorf("no cookie: %v", res)
	}
	if _, res := rdpCookie(request("Cookie: mstshash=x")); res != NoMatch {
		t.Errorf("unterminated cookie: %v", res)
	}
	if _, res := rdpCookie([]byte("GET")); res != NoMatch {
		t.Errorf("http: %v", res)
	}
	// Through an Input, as resolvers see it: an incomplete request that ends
	// has no cookie.
	data := request("Cookie: mstshash=bob\r\n")
	in := NewInput(nil, nil)
	in.SetBytes(data, false)
	if got, res := in.RDPCookie(); res != Match || got != "bob" {
		t.Errorf("Input.RDPCookie = %q, %v", got, res)
	}
	in = NewInput(nil, nil)
	in.SetBytes(data[:10], true)
	if _, res := in.RDPCookie(); res != NoMatch {
		t.Errorf("final partial request: %v", res)
	}
}
