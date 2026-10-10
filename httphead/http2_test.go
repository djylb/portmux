package httphead

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/djylb/portmux/internal/testutil"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHPACKExamples decodes the request examples of RFC 7541, Appendix C,
// without and with Huffman coding, each a sequence that shares the dynamic
// table.
func TestHPACKExamples(t *testing.T) {
	want := [][]string{
		{":method: GET", ":scheme: http", ":path: /", ":authority: www.example.com"},
		{":method: GET", ":scheme: http", ":path: /", ":authority: www.example.com", "cache-control: no-cache"},
		{":method: GET", ":scheme: https", ":path: /index.html", ":authority: www.example.com", "custom-key: custom-value"},
	}
	for name, blocks := range map[string][]string{
		"C.3": {
			"8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
			"8286 84be 5808 6e6f 2d63 6163 6865",
			"8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
		},
		"C.4": {
			"8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
			"8286 84be 5886 a8eb 1064 9cbf",
			"8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
		},
	} {
		d := newHPACKDecoder()
		for i, block := range blocks {
			var got []string
			if err := d.decode(unhex(t, block), func(f hpackField) { got = append(got, f.name+": "+f.value) }); err != nil {
				t.Fatalf("%s.%d: %v", name, i+1, err)
			}
			if strings.Join(got, "\n") != strings.Join(want[i], "\n") {
				t.Fatalf("%s.%d: %q", name, i+1, got)
			}
		}
		if d.size != 164 {
			t.Fatalf("%s: table size %d, want 164", name, d.size)
		}
	}
}

func TestHPACKInvalid(t *testing.T) {
	for name, block := range map[string]string{
		"index 0":            "80",
		"index past tables":  "ff00",
		"truncated integer":  "ff",
		"long integer":       "ffffffffffffffffffffff01",
		"truncated string":   "4005",
		"huffman eos":        "4081ff",
		"table size too big": "3fe21f",
		"bad padding":        "418100",
		"late size update":   "8220",
	} {
		if err := newHPACKDecoder().decode(unhex(t, block), func(hpackField) {}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A small block cannot reference large entries without limit.
	d := newHPACKDecoder()
	big := "40" + "01" + "61" + "7fd10e" + strings.Repeat("62", 2000) // a: 2000 bytes, indexed
	if err := d.decode(unhex(t, big), func(hpackField) {}); err != nil {
		t.Fatal(err)
	}
	if err := d.decode(unhex(t, strings.Repeat("be", 100)), func(hpackField) {}); err == nil {
		t.Fatal("header list beyond the limit")
	}
	// Size updates come first in a block.
	if err := newHPACKDecoder().decode(unhex(t, "203fe11f82"), func(hpackField) {}); err != nil {
		t.Fatalf("size updates before a field: %v", err)
	}
}

//goland:noinspection HttpUrlsUsage
func TestParseHTTP2(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://API.example.com:8080/svc/../v1/Method?x=1", nil)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	data := testutil.H2CBytes(t, req)
	r, err := ParseHTTP2(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "POST" || r.Host != "API.example.com:8080" || r.Path != "/v1/Method" || r.RequestURI != "/svc/../v1/Method?x=1" || r.Proto != "HTTP/2.0" {
		t.Fatalf("request %+v", r)
	}
	if r.Header().Get("Content-Type") != "application/grpc" || r.Query().Get("x") != "1" || r.Name().String() != "api.example.com" {
		t.Fatalf("header %v, query %v, name %v", r.Header(), r.Query(), r.Name())
	}
	// Every prefix is incomplete, and a Scanner needs more than it has.
	var s HTTP2Scanner
	for i := range len(data) {
		if _, err := ParseHTTP2(data[:i]); outcome(err) != "incomplete" {
			t.Fatalf("prefix of %d bytes: %v", i, err)
		}
		if _, err := s.Scan(data[:i]); outcome(err) != "incomplete" || s.Need() <= i {
			t.Fatalf("scan of %d bytes: %v, need %d", i, err, s.Need())
		}
	}
	if r2, err := s.Scan(data); err != nil || r2.Path != r.Path {
		t.Fatalf("scan: %v", err)
	}
	for _, other := range [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n"), []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x01\x00\x00\x00\x00\x01")} {
		if _, err := ParseHTTP2(other); outcome(err) != "invalid" {
			t.Fatalf("%q: %v", other, err)
		}
	}
}

// FuzzParseHTTP2 checks that a decision made on a prefix never changes and
// that a scanner fed in pieces agrees with ParseHTTP2.
//
//goland:noinspection HttpUrlsUsage
func FuzzParseHTTP2(f *testing.F) {
	req, _ := http.NewRequest("GET", "http://www.example.com/a?b=c", nil)
	req.Header.Set("Content-Type", "application/grpc")
	f.Add(testutil.H2CBytes(f, req), uint8(3))
	f.Add([]byte(HTTP2Preface+"\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x0d\x01\x05\x00\x00\x00\x01\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, step uint8) {
		var s HTTP2Scanner
		want, got, wantErr := scanInPieces(t, data, step, ParseHTTP2, s.Scan)
		if wantErr == nil && (got.Method != want.Method || got.Host != want.Host || got.Path != want.Path || got.fields != want.fields) {
			t.Fatalf("pieces: %+v, at once: %+v", got, want)
		}
	})
}

// frame builds an HTTP/2 frame.
func frame(typ, flags byte, stream uint32, payload []byte) []byte {
	b := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags,
		byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	return append(b, payload...)
}

// lit encodes a field as an HPACK literal without indexing.
func lit(name, value string) []byte {
	b := append([]byte{0, byte(len(name))}, name...)
	return append(append(b, byte(len(value))), value...)
}

func block(fields ...[]byte) []byte {
	var b []byte
	for _, f := range fields {
		b = append(b, f...)
	}
	return b
}

func TestParseHTTP2Frames(t *testing.T) {
	settings := frame(frameSettings, 0, 0, nil)
	get := block(lit(":method", "GET"), lit(":scheme", "http"), lit(":path", "/x"), lit(":authority", "a.example"))
	conn := func(frames ...[]byte) []byte {
		b := append([]byte(HTTP2Preface), settings...)
		for _, f := range frames {
			b = append(b, f...)
		}
		return b
	}
	headers := func(flags byte, stream uint32, payload []byte) []byte {
		return frame(frameHeaders, flags|flagEndHeaders, stream, payload)
	}
	var updates [][]byte
	for range http2MaxFrames {
		updates = append(updates, frame(0x8, 0, 0, []byte{0, 0, 0, 1}))
	}
	empty := [][]byte{frame(frameHeaders, 0, 1, get)}
	for range 2 * http2MaxFrames {
		empty = append(empty, frame(frameContinuation, 0, 1, nil))
	}
	empty = append(empty, frame(frameContinuation, flagEndHeaders, 1, nil))
	tests := []struct {
		name, want string
		data       []byte
	}{
		{"plain", "request", conn(headers(0, 1, get))},
		{"padded", "request", conn(headers(flagPadded, 1, append(append([]byte{2}, get...), 0, 0)))},
		{"padding too long", "invalid", conn(headers(flagPadded, 1, append([]byte{byte(len(get) + 1)}, get...)))},
		{"priority", "request", conn(headers(flagPriority, 1, append([]byte{0, 0, 0, 0, 16}, get...)))},
		{"priority too short", "invalid", conn(headers(flagPriority, 1, []byte{0, 0}))},
		{"continuation", "request", conn(frame(frameHeaders, 0, 1, get[:7]), frame(frameContinuation, flagEndHeaders, 1, get[7:]))},
		{"continuation of another stream", "invalid", conn(frame(frameHeaders, 0, 1, get[:7]), frame(frameContinuation, flagEndHeaders, 3, get[7:]))},
		{"stray continuation", "invalid", conn(frame(frameContinuation, flagEndHeaders, 1, get))},
		{"even stream", "invalid", conn(headers(0, 2, get))},
		{"settings ack first", "invalid", append([]byte(HTTP2Preface), frame(frameSettings, flagAck, 0, nil)...)},
		{"headers first", "invalid", append([]byte(HTTP2Preface), headers(0, 1, get)...)},
		{"frame too large", "invalid", conn(frame(0x8, 0, 0, make([]byte, http2MaxFrameSize+1)))},
		{"too many frames", "invalid", conn(append(updates, headers(0, 1, get))...)},
		{"pseudo after regular", "invalid", conn(headers(0, 1, block(lit(":method", "GET"), lit("x", "1"), lit(":scheme", "http"), lit(":path", "/"))))},
		{"pseudo twice", "invalid", conn(headers(0, 1, block(get, lit(":path", "/y"))))},
		{"unknown pseudo", "invalid", conn(headers(0, 1, block(get, lit(":protocol", "x"))))},
		{"no method", "invalid", conn(headers(0, 1, block(lit(":scheme", "http"), lit(":path", "/"))))},
		{"no scheme", "invalid", conn(headers(0, 1, block(lit(":method", "GET"), lit(":path", "/"))))},
		{"absolute path", "invalid", conn(headers(0, 1, block(lit(":method", "GET"), lit(":scheme", "http"), lit(":path", "http://b.example/"))))},
		{"connect", "request", conn(headers(0, 1, block(lit(":method", "CONNECT"), lit(":authority", "b.example:443"))))},
		{"connect with a path", "invalid", conn(headers(0, 1, block(lit(":method", "CONNECT"), lit(":authority", "b"), lit(":path", "/"))))},
		{"line break in a value", "invalid", conn(headers(0, 1, block(get, lit("x", "a\r\nhost: evil"))))},
		{"colon in a name", "invalid", conn(headers(0, 1, block(get, lit("x:y", "1"))))},
		{"two hosts", "invalid", conn(headers(0, 1, block(lit(":method", "GET"), lit(":scheme", "http"), lit(":path", "/"), lit("host", "a"), lit("host", "b"))))},
		{"host header", "request", conn(headers(0, 1, block(lit(":method", "GET"), lit(":scheme", "http"), lit(":path", "/"), lit("host", "c.example"))))},
		{"host as authority", "request", conn(headers(0, 1, block(get, lit("host", "A.example"))))},
		{"host other than authority", "invalid", conn(headers(0, 1, block(get, lit("host", "admin.internal"))))},
		{"uppercase name", "invalid", conn(headers(0, 1, block(get, lit("X-Kind", "1"))))},
		{"uppercase host", "invalid", conn(headers(0, 1, block(lit(":method", "GET"), lit(":scheme", "http"), lit(":path", "/"), lit("host", "a"), lit("HOST", "b"))))},
		{"control character in a value", "invalid", conn(headers(0, 1, block(get, lit("x", "a\x01"))))},
		{"tab in a value", "request", conn(headers(0, 1, block(get, lit("x", "a\tb"))))},
		{"endless continuation", "invalid", conn(empty...)},
		{"bad hpack", "invalid", conn(headers(0, 1, []byte{0x80}))},
	}
	for _, tt := range tests {
		r, err := ParseHTTP2(tt.data)
		if outcome(err) != tt.want {
			t.Errorf("%s: %v, want %s", tt.name, err, tt.want)
			continue
		}
		switch {
		case tt.name == "connect" && (r.Host != "b.example:443" || r.Path != ""):
			t.Errorf("connect: %+v", r)
		case tt.name == "host header" && r.Host != "c.example":
			t.Errorf("host header: %+v", r)
		}
	}
}

func TestHPACKEviction(t *testing.T) {
	d := newHPACKDecoder()
	// Two entries are indexed; a smaller table keeps only the newest.
	add := func(name, value string) []byte {
		b := append([]byte{0x40, byte(len(name))}, name...)
		return append(append(b, byte(len(value))), value...)
	}
	if err := d.decode(block(add("a", "1"), add("b", "2")), func(hpackField) {}); err != nil {
		t.Fatal(err)
	}
	if err := d.decode([]byte{0x20 | 31, 3}, func(hpackField) {}); err != nil { // size update to 34
		t.Fatal(err)
	}
	var got []string
	if err := d.decode([]byte{0x80 | 62}, func(f hpackField) { got = append(got, f.name+f.value) }); err != nil || len(got) != 1 || got[0] != "b2" {
		t.Fatalf("newest entry: %q, %v", got, err)
	}
	if err := d.decode([]byte{0x80 | 63}, func(hpackField) {}); err == nil {
		t.Fatal("evicted entry still indexed")
	}
}

func TestRequestAccessors(t *testing.T) {
	r := &Request{Host: "API.Example.com:8080", RequestURI: "/p#frag"}
	if r.Name().String() != "api.example.com" || len(r.Query()) != 0 {
		t.Fatalf("Name %v, Query %v", r.Name(), r.Query())
	}
	req, err := Parse([]byte("GET /p?a=1#f HTTP/1.1\r\nX: 1\r\nx: 2\r\nHost: h\r\n\r\n"))
	if err != nil || req.Query().Get("a") != "1" {
		t.Fatalf("%v, %v", req, err)
	}
	var values []string
	for v := range req.Values("X") {
		values = append(values, v)
		break
	}
	if len(values) != 1 || values[0] != "1" || len(req.Header()["X"]) != 2 {
		t.Fatalf("Values %q, Header %v", values, req.Header())
	}
	var s Scanner
	if _, err := s.Scan([]byte("GET / HT")); outcome(err) != "incomplete" || s.Need() != 9 {
		t.Fatalf("Scan = %v, Need = %d", err, s.Need())
	}
}
