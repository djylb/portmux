package fingerprint

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/djylb/portmux/internal/testutil"
	"github.com/djylb/portmux/tlshello"
)

func TestJA4(t *testing.T) {
	h, err := tlshello.Parse(testutil.JA4Example())
	if err != nil {
		t.Fatal(err)
	}
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got := JA4(h); got != want {
		t.Fatalf("JA4 = %s, want %s", got, want)
	}
	if !MatchJA4(want).Match(h) || MatchJA4("t13d1516h2_000000000000_000000000000").Match(h) {
		t.Fatal("JA4 filter")
	}
	if got := fmt.Sprint(MatchJA4(want)); got != `JA4("`+want+`")` {
		t.Fatalf("description %s", got)
	}

	// Without signature algorithms, the extensions are hashed alone.
	noSchemes := &tlshello.Hello{Version: h.Version, SupportedVersions: h.SupportedVersions, CipherSuites: h.CipherSuites, Extensions: h.Extensions, ALPN: h.ALPN}
	if got := JA4(noSchemes); got != "t13d1516h2_8daaf6152771_6d807ffa2a79" {
		t.Fatalf("JA4 without signature algorithms = %s", got)
	}
	// GREASE signature algorithms are ignored, as GREASE values are
	// everywhere else.
	greased := *h
	greased.SignatureSchemes = append([]uint16{0x2a2a}, h.SignatureSchemes...)
	if got := JA4(&greased); got != want {
		t.Fatalf("JA4 with a GREASE signature algorithm = %s, want %s", got, want)
	}
	greased.SignatureSchemes = []uint16{0x3a3a}
	if got := JA4(&greased); got != JA4(noSchemes) {
		t.Fatalf("JA4 with only GREASE signature algorithms = %s, want %s", got, JA4(noSchemes))
	}
	tests := []struct {
		name string
		h    *tlshello.Hello
		want string
	}{
		{"nothing", &tlshello.Hello{Version: tls.VersionTLS12}, "t12i000000_000000000000_000000000000"},
		{"ssl 3", &tlshello.Hello{Version: 0x0300, CipherSuites: []uint16{0x0a0a}}, "ts3i000000_000000000000_000000000000"},
		{"unknown version", &tlshello.Hello{Version: 0x7f00}, "t00i000000_000000000000_000000000000"},
		{"only sni and alpn", &tlshello.Hello{Version: tls.VersionTLS12, Extensions: []uint16{0, 16}, ALPN: []string{"http/1.1"}}, "t12d0002h1_000000000000_000000000000"},
		{"one character", &tlshello.Hello{Version: tls.VersionTLS12, ALPN: []string{"x"}}, "t12i0000xx_000000000000_000000000000"},
		{"not alphanumeric", &tlshello.Hello{Version: tls.VersionTLS12, ALPN: []string{"\xab"}}, "t12i0000ab_000000000000_000000000000"},
		{"leading space", &tlshello.Hello{Version: tls.VersionTLS12, ALPN: []string{" a"}}, "t12i000021_000000000000_000000000000"},
		{"trailing space", &tlshello.Hello{Version: tls.VersionTLS12, ALPN: []string{"a "}}, "t12i000060_000000000000_000000000000"},
	}
	for _, tt := range tests {
		if got := JA4(tt.h); got != tt.want {
			t.Errorf("%s: JA4 = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestJA3(t *testing.T) {
	// The example of the JA3 documentation, with GREASE values added.
	suites := []uint16{0x0a0a, 47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4}
	exts := testutil.Ext(0x2a2a, nil)
	exts = append(exts, testutil.Ext(tlshello.ExtensionServerName, testutil.U16List(testutil.SNIEntry(0, "example.com")))...)
	exts = append(exts, testutil.Ext(tlshello.ExtensionSupportedGroups, testutil.U16List(testutil.Values16(23, 24, 25)))...)
	exts = append(exts, testutil.Ext(tlshello.ExtensionPointFormats, []byte{1, 0})...)
	h, err := tlshello.Parse(testutil.HelloRecordWith(tls.VersionTLS10, suites, exts))
	if err != nil {
		t.Fatal(err)
	}
	const want = "ada70206e40642a3e4461f35503241d5"
	if got := JA3(h); got != want {
		t.Fatalf("JA3 = %s", got)
	}
	if !MatchJA3(want).Match(h) || fmt.Sprint(MatchJA3(want)) != `JA3("`+want+`")` {
		t.Fatal("JA3 filter")
	}
}
