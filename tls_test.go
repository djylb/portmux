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
