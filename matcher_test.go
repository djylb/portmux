package portmux

import (
	"regexp"
	"testing"

	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/internal/testutil"
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

// TestNotOnFinalInput checks that Not inverts a matcher that still needs
// more of an input that ended, which the routes count as not matching.
func TestNotOnFinalInput(t *testing.T) {
	for _, tt := range []struct {
		m    Matcher
		data string
	}{
		{SSH(), "SS"},
		{DNS(), "\x00\x1d"},
		{TLS(), "\x16\x03"},
		{HTTP1(), "GET / HTTP/1.1\r\n"},
	} {
		in := NewInput(nil, nil)
		in.SetBytes([]byte(tt.data), false)
		if got := Not(tt.m).Match(in); got != NeedMore {
			t.Errorf("Not(%s) on %q = %v, want NeedMore", describe(tt.m), tt.data, got)
		}
		in.SetBytes([]byte(tt.data), true)
		if got := Not(tt.m).Match(in); got != Match {
			t.Errorf("Not(%s) on final %q = %v, want Match", describe(tt.m), tt.data, got)
		}
	}
}

// TestRegexpDecidesOnce checks that a Regexp matcher keeps its decision for
// the connection, so that it does not run its expression again on every read
// while another matcher of the route waits for more bytes.
func TestRegexpDecidesOnce(t *testing.T) {
	m := Regexp(regexp.MustCompile(`^abcd`), 4)
	in := NewInput(nil, nil)
	in.SetBytes([]byte("abc"), false)
	if got := m.Match(in); got != NeedMore {
		t.Fatalf("3 bytes: %v", got)
	}
	in.SetBytes([]byte("abcd"), false)
	if got := m.Match(in); got != Match {
		t.Fatalf("4 bytes: %v", got)
	}
	// Bytes that do not continue the input are not looked at again...
	in.SetBytes([]byte("zzzzz"), false)
	if got := m.Match(in); got != Match {
		t.Fatalf("decision not kept: %v", got)
	}
	// ...but a shorter input starts over.
	in.SetBytes([]byte("zzzz"), false)
	if got := m.Match(in); got != NoMatch {
		t.Fatalf("after starting over: %v", got)
	}
	// Each matcher keeps its own decision, and those that find no room are
	// decided anew.
	in.SetBytes(nil, false)
	in.SetBytes([]byte("abcd"), false)
	for i := range 6 {
		if got := Regexp(regexp.MustCompile(`^abc`), 3+i%2).Match(in); got != Match {
			t.Fatalf("matcher %d: %v", i, got)
		}
	}
}

// TestFiltersDoNotAllocate checks the filters of a parsed request.
func TestFiltersDoNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates")
	}
	m := HTTP1(
		HostRegexp(regexp.MustCompile(`^www\.`)), PathRegexp(regexp.MustCompile(`^/a`)),
		HeaderRegexp("User-Agent", regexp.MustCompile(`curl`)), Header("Accept"), Host("*.example.com"),
	)
	in := NewInput(nil, nil)
	in.SetBytes([]byte("GET /a HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n"), false)
	if got := m.Match(in); got != Match {
		t.Fatalf("Match = %v", got)
	}
	if n := testing.AllocsPerRun(100, func() { m.Match(in) }); n != 0 {
		t.Fatalf("%v allocations", n)
	}
	m = TLS(SNIRegexp(regexp.MustCompile(`^www\.`)), SNI("*.example.com"))
	in.SetBytes(nil, false)
	in.SetBytes(testutil.SNIHello("www.example.com"), false)
	if got := m.Match(in); got != Match {
		t.Fatalf("TLS Match = %v", got)
	}
	if n := testing.AllocsPerRun(100, func() { m.Match(in) }); n != 0 {
		t.Fatalf("TLS: %v allocations", n)
	}
}
