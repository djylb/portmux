package portmux

import (
	"testing"

	"github.com/djylb/portmux/httphead"
)

func TestPrefix(t *testing.T) {
	m := Prefix("TST", "TLS")
	tests := []struct {
		data string
		want Result
	}{
		{"", NeedMore},
		{"T", NeedMore},
		{"TS", NeedMore},
		{"TST", Match},
		{"TLS!", Match},
		{"TX", NoMatch},
		{"GET", NoMatch},
	}
	for _, tt := range tests {
		if got := m.Match(&Input{data: []byte(tt.data)}); got != tt.want {
			t.Errorf("Prefix(%q) = %v, want %v", tt.data, got, tt.want)
		}
	}
	if got := Prefix("").Match(&Input{data: []byte("x")}); got != Match {
		t.Errorf("empty prefix = %v", got)
	}
}

func TestBuiltinPrefixMatchers(t *testing.T) {
	check := func(name string, m Matcher, data string, want Result) {
		t.Helper()
		if got := m.Match(&Input{data: []byte(data)}); got != want {
			t.Errorf("%s(%q) = %v, want %v", name, data, got, want)
		}
	}
	check("SSH", SSH(), "SSH-2.0-OpenSSH_9.6\r\n", Match)
	check("SSH", SSH(), "SSH", NeedMore)
	check("SSH", SSH(), "GET", NoMatch)
	check("HTTP2Preface", HTTP2Preface(), httphead.HTTP2Preface, Match)
	check("HTTP2Preface", HTTP2Preface(), "PRI * HTTP/2.0\r\n", NeedMore)
	check("HTTP2Preface", HTTP2Preface(), "PRI * HTTP/1.1", NoMatch)
	check("Any", Any(), "x", Match)
	check("Any", Any(), "", NeedMore)
}

func TestResultString(t *testing.T) {
	for r, want := range map[Result]string{NoMatch: "NoMatch", Match: "Match", NeedMore: "NeedMore", 9: "Result(9)"} {
		if got := r.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

func TestInputCachesParses(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: h\r\n")
	in := &Input{data: data}
	if _, res := in.HTTPRequest(); res != NeedMore {
		t.Fatalf("partial = %v", res)
	}
	in.data = append(data, "\r\n"...)
	req, res := in.HTTPRequest()
	if res != Match || req == nil || req.Host != "h" {
		t.Fatalf("complete = %+v, %v", req, res)
	}
	again, _ := in.HTTPRequest()
	if again != req {
		t.Fatal("request parsed twice")
	}
	if _, res := in.ClientHello(); res != NoMatch {
		t.Fatalf("ClientHello = %v", res)
	}

	partial := &Input{data: data[:5]}
	if _, res := partial.HTTPRequest(); res != NeedMore {
		t.Fatalf("partial = %v", res)
	}
	partial.final = true
	if _, res := partial.HTTPRequest(); res != NoMatch {
		t.Fatalf("partial on final = %v, want NoMatch", res)
	}
}
