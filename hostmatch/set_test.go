package hostmatch

import (
	"strings"
	"testing"
)

func TestSplitHost(t *testing.T) {
	tests := map[string]string{
		"example.com":      "example.com",
		"example.com:80":   "example.com",
		"[::1]:443":        "::1",
		"[::1]":            "::1",
		"::1":              "::1",
		"127.0.0.1:8080":   "127.0.0.1",
		"":                 "",
		"[broken":          "[broken",
		"example.com.:443": "example.com.",
	}
	for in, want := range tests {
		if got := SplitHost(in); got != want {
			t.Errorf("SplitHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetMatch(t *testing.T) {
	tests := []struct {
		patterns []string
		host     string
		want     bool
	}{
		{[]string{"example.com"}, "EXAMPLE.com", true},
		{[]string{"example.com."}, "example.com", true},
		{[]string{"example.com"}, "example.com.", true},
		{[]string{"*.example.com"}, "a.b.example.com", true},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"*.example.com"}, "badexample.com", false},
		{[]string{"*"}, "x", true},
		{[]string{"*"}, "", false},
		{[]string{""}, "", true},
		{[]string{"a", "b"}, "b", true},
		{nil, "a", false},
	}
	for _, tt := range tests {
		if got := NewSet(tt.patterns...).Match(tt.host); got != tt.want {
			t.Errorf("matchHost(%q, %q) = %v, want %v", tt.patterns, tt.host, got, tt.want)
		}
	}
}

func TestSetWildcards(t *testing.T) {
	tests := []struct {
		pattern, host string
		want          bool
	}{
		{"api-*.example.com", "api-1.example.com", true},
		{"api-*.example.com", "API-x.y.Example.com.", true},
		{"api-*.example.com", "api-.example.com", false},
		{"api-*.example.com", "www.example.com", false},
		{"*.*.example.com", "a.b.example.com", true},
		{"*.*.example.com", "a.example.com", false},
		{"*example.com", "myexample.com", true},
		{"*example.com", "example.com", false},
		{"www.*", "www.example.org", true},
		{"*.example.com", "evil@x.example.com", false},
	}
	for _, tt := range tests {
		if got := NewSet(tt.pattern).Match(tt.host); got != tt.want {
			t.Errorf("%q on %q = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestNameValidation(t *testing.T) {
	hosts := NewSet([]string{"*.example.com", "::1", "*"}...)
	for host, want := range map[string]bool{
		"a.example.com":          true,
		"evil@admin.example.com": false,
		"a.example.com\x00x":     false,
		"bad host":               false,
		"::1":                    true,
		"münchen.example.com":    false,
		"xn--mnchen-3ya.example": true,
	} {
		if got := hosts.Match(host); got != want {
			t.Errorf("match(%q) = %v, want %v", host, got, want)
		}
	}
	if n := Normalize("Evil@Admin.example.com."); n.Valid() {
		t.Fatalf("Normalize(%q) is valid", n)
	}
	if n := Normalize("WWW.Example.COM."); !n.Valid() || n.String() != "www.example.com" {
		t.Fatalf("Normalize = %q, %v", n, n.Valid())
	}
	// A Host value without a name is not the empty name of a request without
	// a Host.
	empty := NewSet("", "*")
	for _, host := range []string{":80", "[]", "[]:443", "."} {
		if n := NormalizeHost(host); n.Valid() || empty.MatchName(n) {
			t.Errorf("NormalizeHost(%q) = %q, valid %v", host, n, n.Valid())
		}
	}
	if !empty.MatchName(NormalizeHost("")) || NormalizeHost("[::1]:443").String() != "::1" || NormalizeHost("A.example:8080").String() != "a.example" {
		t.Error("NormalizeHost of a valid host")
	}
	if s := NewSet("*.example.com", ""); s.String() != `Set("*.example.com", "")` || len(s.Patterns()) != 2 {
		t.Fatalf("String = %s", s)
	}
}

func TestSetIndex(t *testing.T) {
	var names []string
	for i := range indexMin + 2 {
		names = append(names, "h"+strings.Repeat("x", i)+".example")
	}
	hosts := NewSet(append(names, "*.wild.example")...)
	if hosts.index == nil {
		t.Fatal("no index for many names")
	}
	for _, host := range []string{"hxx.example", "HXXX.Example.", "a.wild.example"} {
		if !hosts.Match(host) {
			t.Errorf("%q did not match", host)
		}
	}
	if hosts.Match("other.example") || hosts.Match("") {
		t.Error("unexpected match")
	}
}
