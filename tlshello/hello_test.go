package tlshello

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/internal/testutil"
)

// outcome names the result of a parse as the tables compare it.
func outcome(err error) string {
	switch {
	case err == nil:
		return "hello"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "incomplete"
	case errors.Is(err, ErrInvalid):
		return "invalid"
	}
	return err.Error()
}

func TestParseFromCryptoTLS(t *testing.T) {
	data := testutil.ClientHelloBytes(t, &tls.Config{
		ServerName:         "App.Example.com",
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	})
	h, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if h.ServerName != "App.Example.com" || h.Name() != hostmatch.Normalize("app.example.com") {
		t.Errorf("ServerName = %q, Name = %v", h.ServerName, h.Name())
	}
	if !slices.Equal(h.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("ALPN = %q", h.ALPN)
	}
	if h.Version != tls.VersionTLS12 || !slices.Contains(h.SupportedVersions, tls.VersionTLS13) || h.MaxVersion() != tls.VersionTLS13 {
		t.Errorf("Version = %#x, SupportedVersions = %#x", h.Version, h.SupportedVersions)
	}
	end := recordHeaderLen + int(binary.BigEndian.Uint16(data[3:5]))
	for i := range end {
		if _, err := Parse(data[:i]); outcome(err) != "incomplete" {
			t.Fatalf("prefix of %d bytes: %v", i, err)
		}
	}
	if h, err := Parse(testutil.ClientHelloBytes(t, &tls.Config{InsecureSkipVerify: true})); err != nil || h.ServerName != "" || h.ALPN != nil {
		t.Fatalf("without SNI: %+v, %v", h, err)
	}
}

func TestParseFragmented(t *testing.T) {
	whole := testutil.ClientHelloBytes(t, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	msg := whole[recordHeaderLen : recordHeaderLen+int(binary.BigEndian.Uint16(whole[3:5]))]
	var data []byte
	for chunk := range slices.Chunk(msg, 100) {
		data = append(data, recordTypeHandshake, 3, 1, byte(len(chunk)>>8), byte(len(chunk)))
		data = append(data, chunk...)
	}
	if h, err := Parse(data); err != nil || h.ServerName != "example.com" {
		t.Fatalf("parse = %+v, %v", h, err)
	}
	// A Scanner consumes complete records once and tells how much it needs.
	var s Scanner
	for i := range data {
		if _, err := s.Scan(data[:i]); outcome(err) != "incomplete" {
			t.Fatalf("prefix of %d bytes: %v", i, err)
		}
		if s.Need() <= i {
			t.Fatalf("need %d after %d bytes", s.Need(), i)
		}
	}
	if h, err := s.Scan(data); err != nil || h.ServerName != "example.com" {
		t.Fatalf("scan = %+v, %v", h, err)
	}
}

func TestParseCrafted(t *testing.T) {
	sni := func(entries ...[]byte) []byte { return testutil.Ext(ExtensionServerName, testutil.U16List(entries...)) }
	tests := []struct {
		name, want string
		data       []byte
		sni        string
	}{
		{"no extensions", "hello", testutil.HelloRecord(nil), ""},
		{"empty extensions", "hello", testutil.HelloRecord([]byte{}), ""},
		{"sni", "hello", testutil.HelloRecord(sni(testutil.SNIEntry(0, "a.example"))), "a.example"},
		{"other name type ignored", "hello", testutil.HelloRecord(sni(testutil.SNIEntry(7, "x"), testutil.SNIEntry(0, "a.example"))), "a.example"},
		{"unknown extension", "hello", testutil.HelloRecord(testutil.Ext(0xff01, []byte{0})), ""},
		{"two host names", "invalid", testutil.HelloRecord(sni(testutil.SNIEntry(0, "a"), testutil.SNIEntry(0, "b"))), ""},
		{"trailing dot", "invalid", testutil.HelloRecord(sni(testutil.SNIEntry(0, "a.example."))), ""},
		{"empty name", "invalid", testutil.HelloRecord(sni(testutil.SNIEntry(0, ""))), ""},
		{"empty sni extension", "invalid", testutil.HelloRecord(testutil.Ext(ExtensionServerName, nil)), ""},
		{"duplicate extension", "invalid", testutil.HelloRecord(append(testutil.Ext(0xff01, nil), testutil.Ext(0xff01, nil)...)), ""},
		{"empty alpn protocol", "invalid", testutil.HelloRecord(testutil.Ext(ExtensionALPN, testutil.U16List([]byte{0}))), ""},
		{"odd supported versions", "invalid", testutil.HelloRecord(testutil.Ext(ExtensionSupportedVersions, []byte{3, 3, 4, 3})), ""},
		{"truncated extension", "invalid", testutil.HelloRecord([]byte{0, 0, 0, 5, 1}), ""},
		{"application data record", "invalid", []byte{23, 3, 3, 0, 5}, ""},
		{"record version 3.5", "invalid", []byte{recordTypeHandshake, 3, 5}, ""},
		{"empty record", "invalid", []byte{recordTypeHandshake, 3, 1, 0, 0}, ""},
		{"oversized record", "invalid", []byte{recordTypeHandshake, 3, 1, 0x40, 0x01}, ""},
		{"server hello", "invalid", []byte{recordTypeHandshake, 3, 3, 0, 4, 2}, ""},
		{"http", "invalid", []byte("GET / HTTP/1.1\r\n"), ""},
		{"partial header", "incomplete", []byte{recordTypeHandshake, 3}, ""},
	}
	for _, tt := range tests {
		h, err := Parse(tt.data)
		if outcome(err) != tt.want {
			t.Errorf("%s: %v, want %s", tt.name, err, tt.want)
			continue
		}
		if err == nil && h.ServerName != tt.sni {
			t.Errorf("%s: ServerName = %q, want %q", tt.name, h.ServerName, tt.sni)
		}
	}
	// Duplicates are found among many extensions too.
	var many []byte
	for i := range uint16(100) {
		many = append(many, testutil.Ext(0x1000+i, nil)...)
	}
	if _, err := Parse(testutil.HelloRecord(many)); err != nil {
		t.Fatalf("100 extensions: %v", err)
	}
	for _, dup := range []uint16{0x1000, 0x101f, 0x1020, 0x1063} {
		if _, err := Parse(testutil.HelloRecord(append(slices.Clip(many), testutil.Ext(dup, nil)...))); outcome(err) != "invalid" {
			t.Errorf("duplicate %#x after 100 extensions: %v", dup, err)
		}
	}
	// Bytes in the handshake body after the hello make it invalid.
	rec := testutil.HelloRecord(nil)
	rec = append(rec, 0)
	binary.BigEndian.PutUint16(rec[3:5], binary.BigEndian.Uint16(rec[3:5])+1)
	rec[8]++
	if _, err := Parse(rec); outcome(err) != "invalid" {
		t.Fatalf("trailing body bytes: %v", err)
	}
}

func TestHelloFields(t *testing.T) {
	h, err := Parse(testutil.JA4Example())
	if err != nil {
		t.Fatal(err)
	}
	if len(h.CipherSuites) != 16 || h.CipherSuites[0] != 0x2a2a || h.CipherSuites[15] != 0x0035 {
		t.Errorf("CipherSuites = %#x", h.CipherSuites)
	}
	if len(h.Extensions) != 18 || h.Extensions[1] != 0x001b || h.Extensions[17] != 0x1a1a {
		t.Errorf("Extensions = %#x", h.Extensions)
	}
	if !slices.Equal(h.SupportedGroups, []uint16{0x4a4a, 0x001d, 0x0017, 0x0018}) {
		t.Errorf("SupportedGroups = %#x", h.SupportedGroups)
	}
	if len(h.SignatureSchemes) != 8 || h.SignatureSchemes[0] != 0x0403 {
		t.Errorf("SignatureSchemes = %#x", h.SignatureSchemes)
	}
	if !slices.Equal(h.PointFormats, []uint8{0}) || h.MaxVersion() != tls.VersionTLS13 {
		t.Errorf("PointFormats = %v, MaxVersion = %#x", h.PointFormats, h.MaxVersion())
	}
	// The lists share one array but do not grow into each other.
	grown := append(h.CipherSuites, 0xffff)
	if h.Extensions[0] != 0x0a0a || &grown[0] == &h.CipherSuites[0] {
		t.Error("appending to a list overwrote another")
	}
	if !IsGREASE(0x2a2a) || IsGREASE(0x2a3a) || IsGREASE(0x0303) {
		t.Error("IsGREASE")
	}

	bare, err := Parse(testutil.HelloRecord(nil))
	if err != nil || bare.Extensions != nil || bare.SupportedGroups != nil || bare.SignatureSchemes != nil || bare.PointFormats != nil {
		t.Errorf("hello without extensions: %+v", bare)
	}
	for name, e := range map[string][]byte{
		"odd groups":         testutil.Ext(ExtensionSupportedGroups, []byte{0, 1, 0}),
		"empty groups":       testutil.Ext(ExtensionSupportedGroups, []byte{0, 0}),
		"empty schemes":      testutil.Ext(ExtensionSignatureAlgorithms, []byte{0, 0}),
		"empty formats":      testutil.Ext(ExtensionPointFormats, []byte{0}),
		"formats trailing":   testutil.Ext(ExtensionPointFormats, []byte{1, 0, 0}),
		"groups trailing":    testutil.Ext(ExtensionSupportedGroups, append(testutil.U16List(testutil.Values16(0x1d)), 0)),
		"versions too short": testutil.Ext(ExtensionSupportedVersions, []byte{2, 3}),
	} {
		if _, err := Parse(testutil.HelloRecord(e)); outcome(err) != "invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A Hello built by hand prepares its name on demand.
	if (&Hello{ServerName: "A.example."}).Name().String() != "a.example" {
		t.Error("Name of a Hello built by hand")
	}
}

func BenchmarkParse(b *testing.B) {
	data := testutil.ClientHelloBytes(b, &tls.Config{ServerName: "www.example.com", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseManyExtensions parses a hello with as many empty extensions
// as one record holds, which costs time in proportion to its size.
func BenchmarkParseManyExtensions(b *testing.B) {
	var exts []byte
	for i := range uint16(4000) {
		exts = append(exts, testutil.Ext(0x1000+i, nil)...)
	}
	data := testutil.HelloRecord(exts)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzParse checks that a Scanner fed in pieces agrees with Parse, that a
// decision made on a prefix never changes, and that Need is beyond the data
// while more is needed.
func FuzzParse(f *testing.F) {
	f.Add(testutil.ClientHelloBytes(f, &tls.Config{ServerName: "a.example.com", NextProtos: []string{"h2"}, InsecureSkipVerify: true}))
	f.Add(testutil.HelloRecord(nil))
	f.Add(testutil.SNIHello("x"))
	f.Add(testutil.JA4Example())
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, want := Parse(data)
		var s Scanner
		got := io.ErrUnexpectedEOF
		for n := 0; outcome(got) == "incomplete" && n < len(data); {
			n = min(n+7, len(data))
			_, got = s.Scan(data[:n])
		}
		if outcome(got) != outcome(want) {
			t.Fatalf("pieces: %v, at once: %v", got, want)
		}
		for i := range len(data) {
			var s Scanner
			_, err := s.Scan(data[:i])
			switch o := outcome(err); {
			case o == "incomplete" && s.Need() <= i:
				t.Fatalf("incomplete with need %d for %d bytes", s.Need(), i)
			case o != "incomplete" && o != outcome(want):
				t.Fatalf("prefix of %d bytes: %v, whole: %v", i, err, want)
			}
		}
	})
}
