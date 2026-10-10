package portmux

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/djylb/portmux/fingerprint"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/internal/testutil"
	"github.com/djylb/portmux/tlshello"
)

// TestParseMatcherRoundTrip parses the description of every built-in matcher
// and filter back into a matcher with the same description.
func TestParseMatcherRoundTrip(t *testing.T) {
	var many []netip.Prefix
	for i := range 20 {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16))
	}
	many = append(many, netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:db9::/32"))
	matchers := []Matcher{
		Any(), Always(), SSH(), HTTP2Preface(), SOCKS4(), SOCKS5(), PostgreSQL(), MQTT(), RDP(), OpenVPN(), XMPP(), DNS(),
		Prefix("TST", "a\"b\x00"), Domain("*.example.com", ""), Regexp(regexp.MustCompile(`^[A-Z]+ \S+ RTSP`), 32),
		Silent(1500 * time.Millisecond),
		RemoteIP(netip.MustParsePrefix("192.168.1.7/24"), netip.MustParsePrefix("::1/128")), RemoteIP(many...), LocalIP(), LocalPort(80, 443),
		And(Not(RemoteIP(netip.MustParsePrefix("10.0.0.0/8"))), Or(TLS(), HTTP1())),
		HTTP1(Host("a.example.com", "*"), Path("/x"), PathPrefix("/api/"), Method("GET", "POST"),
			HostRegexp(regexp.MustCompile(`^api\d+\.`)), PathRegexp(regexp.MustCompile(`\.php$`)),
			Header("Connection", "upgrade"), Header("X-Any"), HeaderRegexp("User-Agent", regexp.MustCompile(`(?i)curl`)),
			Query("v", "1", "2"), Query("debug"), WebSocket(),
			AllOf(AnyOf(Host("b"), NoneOf(Path("/admin"))))),
		HTTP2(Header("content-type", "application/grpc")),
		HTTP1(HeaderRegexp("", regexp.MustCompile(`x`))), Regexp(regexp.MustCompile(`x`), math.MaxInt),
		TLS(SNI("a", "*.b"), SNIRegexp(regexp.MustCompile(`^x`)), ALPN("h2"), MinTLSVersion(0x0303), MinTLSVersion(0x0300),
			NoneOf(SNI("c"))),
	}
	for _, m := range matchers {
		text := describe(m)
		got, err := ParseMatcher(text, nil)
		if err != nil {
			t.Errorf("%s: %v", text, err)
			continue
		}
		if again := describe(got); again != text {
			t.Errorf("%s parsed as %s", text, again)
		}
	}

	// Parsed matchers behave like the originals.
	m, err := ParseMatcher(`And(RemoteIP(10.0.0.0/8), HTTP1(Host("*.example.com"), NoneOf(PathPrefix("/admin"))))`, nil)
	if err != nil {
		t.Fatal(err)
	}
	for data, want := range map[string]Result{
		"GET /x HTTP/1.1\r\nHost: a.example.com\r\n\r\n":     Match,
		"GET /admin HTTP/1.1\r\nHost: a.example.com\r\n\r\n": NoMatch,
	} {
		in := NewInput(addrConnAddr("10.1.2.3:4"), nil)
		in.SetBytes([]byte(data), false)
		if got := m.Match(in); got != want {
			t.Errorf("%q: %v", data, got)
		}
	}
	// Addresses stand for single prefixes, and whitespace is free.
	m, err = ParseMatcher(" RemoteIP( 10.1.2.3 ,\n2001:db8::1 ) ", nil)
	if err != nil || describe(m) != "RemoteIP(10.1.2.3/32, 2001:db8::1/128)" {
		t.Fatalf("%v, %v", m, err)
	}
	// Raw strings work as in Go.
	if m, err := ParseMatcher("Prefix(`a\\b`)", nil); err != nil || describe(m) != `Prefix("a\\b")` {
		t.Fatalf("%v, %v", m, err)
	}
}

func addrConnAddr(s string) *netAddr { return &netAddr{s} }

type netAddr struct{ s string }

func (a *netAddr) Network() string { return "tcp" }
func (a *netAddr) String() string  { return a.s }

func TestParseMatcherNames(t *testing.T) {
	office := RemoteIP(netip.MustParsePrefix("10.0.0.0/8"))
	internal := HTTPFilterFunc(func(r *httphead.Request) bool { return r.Header().Get("X-Internal") != "" })
	modern := TLSFilterFunc(func(h *tlshello.Hello) bool { return h.MaxVersion() >= 0x0304 })
	names := &Names{
		Matchers:    map[string]Matcher{"office": office},
		HTTPFilters: map[string]HTTPFilter{"internal": internal},
		TLSFilters:  map[string]TLSFilter{"modern": modern},
	}
	const text = `Or(And(office, TLS(modern, SNI("a"))), HTTP1(internal))`
	m, err := ParseMatcher(text, names)
	if err != nil {
		t.Fatal(err)
	}
	if describe(m) != text {
		t.Fatalf("description %s", describe(m))
	}
	in := NewInput(addrConnAddr("192.0.2.1:1"), nil)
	in.SetBytes([]byte("GET / HTTP/1.1\r\nX-Internal: 1\r\n\r\n"), false)
	if m.Match(in) != Match {
		t.Fatal("named filter")
	}
}

func TestParseMatcherErrors(t *testing.T) {
	tests := []struct {
		text   string
		offset int
	}{
		{``, 0},
		{`Unknown()`, 0},
		{`office`, 0},
		{`TLS(SNI(a))`, 8},
		{`HTTP1(Host("a")`, 15},
		{`HTTP1(Host("a") Path("/"))`, 16},
		{`Prefix("a`, 7},
		{`Prefix("a") x`, 12},
		{`Not()`, 0},
		{`Not(Any(), Any())`, 0},
		{`Silent(soon)`, 7},
		{`RemoteIP(10.0.0.300/8)`, 9},
		{`LocalPort(70000)`, 10},
		{`Regexp("(", 4)`, 7},
		{`TLS(MinTLSVersion(TLS1.2))`, 18},
		{`TLS(Host("a"))`, 4},
		{`HTTP1(SNI("a"))`, 6},
		{`HTTP1(WebSocket(1))`, 6},
		{`Any(1)`, 0},
		{`And("a")`, 4},
		{`HTTP1("a")`, 6},
		{`Header()`, 0},
		{`HTTP1(Header())`, 6},
		{`,`, 0},
	}
	for _, tt := range tests {
		_, err := ParseMatcher(tt.text, nil)
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Offset != tt.offset || pe.Text != tt.text {
			t.Errorf("%s: %v, want offset %d", tt.text, err, tt.offset)
		}
	}
}

func FuzzParseMatcher(f *testing.F) {
	f.Add(`And(RemoteIP(10.0.0.0/8), TLS(SNI("*.example.com"), MinTLSVersion(1.2)))`)
	f.Add(`HTTP1(Host("a"), AllOf(Header("X", "y"), NoneOf(Path("/"))), Query("q"))`)
	f.Add("Prefix(`raw`, \"q\\\"\")")
	f.Fuzz(func(t *testing.T, text string) {
		m, err := ParseMatcher(text, nil)
		if err != nil {
			return
		}
		// What parses prints text that parses to the same description.
		again, err := ParseMatcher(fmt.Sprint(m), nil)
		if err != nil || fmt.Sprint(again) != fmt.Sprint(m) {
			t.Fatalf("%q printed as %q: %v", text, fmt.Sprint(m), err)
		}
	})
}

// TestParseMatcherFuncs builds calls with arguments from Names, as for the
// filters of the fingerprint package or a matcher of your own.
func TestParseMatcherFuncs(t *testing.T) {
	names := &Names{
		MatcherFuncs: map[string]func(args ...string) (Matcher, error){
			"Country": func(args ...string) (Matcher, error) {
				if len(args) == 0 {
					return nil, errors.New("no country")
				}
				return Named(fmt.Sprintf("Country(%q)", args[0]), Any()), nil
			},
		},
		HTTPFilterFuncs: map[string]func(args ...string) (HTTPFilter, error){
			"Agent": func(args ...string) (HTTPFilter, error) { return Header("User-Agent", args...), nil },
		},
		TLSFilterFuncs: map[string]func(args ...string) (TLSFilter, error){
			"JA4": func(args ...string) (TLSFilter, error) { return fingerprint.MatchJA4(args...), nil },
		},
	}
	const text = `Or(Country("CN"), TLS(JA4("t13d1516h2_8daaf6152771_e5627efa2ab1")))`
	m, err := ParseMatcher(text, names)
	if err != nil {
		t.Fatal(err)
	}
	if describe(m) != text {
		t.Fatalf("description %s", describe(m))
	}
	in := NewInput(nil, nil)
	in.SetBytes(testutil.JA4Example(), false)
	if TLS(fingerprint.MatchJA4("t13d1516h2_8daaf6152771_e5627efa2ab1")).Match(in) != Match {
		t.Fatal("JA4 filter in TLS")
	}
	if _, err := ParseMatcher(`HTTP1(Agent(curl))`, names); err != nil {
		t.Fatal(err)
	}
	for text, offset := range map[string]int{`Country()`: 0, `Country(Any())`: 8, `TLS(JA5("x"))`: 4} {
		var pe *ParseError
		if _, err := ParseMatcher(text, names); !errors.As(err, &pe) || pe.Offset != offset {
			t.Errorf("%s: %v, want offset %d", text, err, offset)
		}
	}
}
