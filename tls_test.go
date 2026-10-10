package portmux

import (
	"crypto/tls"
	"testing"

	"github.com/djylb/portmux/internal/testutil"
	"github.com/djylb/portmux/tlshello"
)

func TestTLSFilters(t *testing.T) {
	hello := &tlshello.Hello{ServerName: "API.Example.com", ALPN: []string{"h2", "http/1.1"}}
	tests := []struct {
		name   string
		filter TLSFilter
		want   bool
	}{
		{"sni exact", SNI("api.example.com"), true},
		{"sni other", SNI("www.example.com"), false},
		{"sni wildcard", SNI("*.example.com"), true},
		{"sni any", SNI("*"), true},
		{"sni empty", SNI(""), false},
		{"alpn", ALPN("h2"), true},
		{"alpn missing", ALPN("acme-tls/1"), false},
	}
	for _, tt := range tests {
		if got := tt.filter.Match(hello); got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
		}
	}
	if !SNI("").Match(&tlshello.Hello{}) || SNI("*").Match(&tlshello.Hello{}) {
		t.Error("empty SNI handling")
	}
}

func TestTLSMatcher(t *testing.T) {
	data := testutil.ClientHelloBytes(t, &tls.Config{ServerName: "a.example.com", InsecureSkipVerify: true})
	check := func(m Matcher, data []byte, final bool, want Result) {
		t.Helper()
		if got := m.Match(&Input{data: data, final: final}); got != want {
			t.Fatalf("Match = %v, want %v", got, want)
		}
	}
	check(TLS(), data, false, Match)
	check(TLS(SNI("a.example.com")), data, false, Match)
	check(TLS(SNI("a.example.com"), ALPN("h2")), data, false, NoMatch)
	check(TLS(SNI("b.example.com")), data, false, NoMatch)
	check(TLS(), data[:10], false, NeedMore)
	check(TLS(), data[:10], true, NoMatch)
}

// TestMinTLSVersionNegotiation judges the version as servers negotiate it.
func TestMinTLSVersionNegotiation(t *testing.T) {
	tests := []struct {
		name  string
		hello tlshello.Hello
		want  uint16 // the highest version accepted
	}{
		{"tls 1.3", tlshello.Hello{Version: tls.VersionTLS12, SupportedVersions: []uint16{0x2a2a, tls.VersionTLS13, tls.VersionTLS12}}, tls.VersionTLS13},
		{"tls 1.2", tlshello.Hello{Version: tls.VersionTLS12}, tls.VersionTLS12},
		{"tls 1.0", tlshello.Hello{Version: tls.VersionTLS10}, tls.VersionTLS10},
		{"legacy 1.3 alone", tlshello.Hello{Version: tls.VersionTLS13}, tls.VersionTLS12},
		{"unknown versions", tlshello.Hello{Version: tls.VersionTLS12, SupportedVersions: []uint16{0x0306, 0x0305, tls.VersionTLS11}}, tls.VersionTLS11},
		{"only grease", tlshello.Hello{Version: tls.VersionTLS12, SupportedVersions: []uint16{0x3a3a}}, 0},
	}
	for _, tt := range tests {
		for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
			if got := MinTLSVersion(v).Match(&tt.hello); got != (v <= tt.want) {
				t.Errorf("%s: MinTLSVersion(%#x) = %v", tt.name, v, got)
			}
		}
	}
}
