package portmux

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/internal/testutil"
	"github.com/djylb/portmux/tlshello"
)

// domainTable stands for the host index of an application: names map to
// routes and change while the Mux serves.
type domainTable struct {
	mu     sync.RWMutex
	routes map[string]*Route
}

func (d *domainTable) set(name string, r *Route) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.routes == nil {
		d.routes = make(map[string]*Route)
	}
	d.routes[name] = r
}

func (d *domainTable) lookup(name string) *Route {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.routes[name]
}

// resolve routes TLS by SNI and HTTP by Host, as a TCP tunnel bound to a
// domain would be.
func (d *domainTable) resolve(in *Input) (*Route, Result) {
	hello, tlsRes := in.ClientHello()
	if tlsRes == Match && hello != nil {
		if r := d.lookup(hello.ServerName); r != nil {
			return r, Match
		}
		return nil, NoMatch
	}
	req, httpRes := in.HTTPRequest()
	if httpRes == Match && req != nil {
		if r := d.lookup(hostmatch.SplitHost(req.Host)); r != nil {
			return r, Match
		}
		return nil, NoMatch
	}
	if tlsRes == NeedMore || httpRes == NeedMore {
		return nil, NeedMore
	}
	return nil, NoMatch
}

func TestResolverRoutesByDomain(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	var domains domainTable
	resolver := mustAdd(t, m, RouteConfig{Name: "domains", Priority: 10, Resolve: domains.resolve})
	// One target per tunnel: no matchers, reached only through the resolver.
	tunnelA := mustAdd(t, m, RouteConfig{Name: "tunnel-a"})
	tunnelB := mustAdd(t, m, RouteConfig{Name: "tunnel-b"})
	blocked := mustAdd(t, m, RouteConfig{Name: "blocked", Reject: true})
	web := m.Match(HTTP1())
	serve(t, m)
	domains.set("a.example.com", tunnelA)
	domains.set("b.example.com", tunnelB)
	domains.set("bad.example.com", blocked)

	// TLS passes through untouched: the handshake runs on the target.
	serveTLSNames(t, tunnelA, "tunnel-a")
	if got := tlsRequest(t, m, "a.example.com"); got != "tunnel-a|a.example.com|a.example.com" {
		t.Fatalf("got %q", got)
	}
	// HTTP by Host, sent in small pieces.
	c := dial(t, m)
	for _, part := range []string{"GET / HT", "TP/1.1\r\nHo", "st: b.example.com:80\r\n\r\n"} {
		_, _ = c.Write([]byte(part))
		time.Sleep(5 * time.Millisecond)
	}
	got := accept(t, tunnelB)
	if got.Route() != tunnelB || got.HTTPRequest().Host != "b.example.com:80" {
		t.Fatalf("route %v, request %+v", got.Route(), got.HTTPRequest())
	}
	// Unknown names fall through to the next routes.
	_, _ = dial(t, m).Write([]byte("GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n"))
	accept(t, web)
	// The table can send a name to a reject route.
	c = dial(t, m)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: bad.example.com\r\n\r\n"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrRefused) {
		t.Fatalf("reported %v", err)
	}
	// Changes to the table apply at once, without touching the routes.
	domains.set("other.example.com", tunnelB)
	_, _ = dial(t, m).Write([]byte("GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n"))
	if got := accept(t, tunnelB); got.HTTPRequest().Host != "other.example.com" {
		t.Fatalf("request %+v", got.HTTPRequest())
	}

	info := resolver.Info()
	if !info.Resolver || !info.Active || info.Matched != 4 {
		t.Fatalf("resolver info %+v", info)
	}
	if info := tunnelB.Info(); info.Active || info.Matched != 2 {
		t.Fatalf("target info %+v", info)
	}
}

func TestResolverEdgeCases(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	closed := mustAdd(t, m, RouteConfig{Name: "closed"})
	_ = closed.Close()
	other := New()
	foreign := other.Match(Any())
	self := mustAdd(t, m, RouteConfig{Resolve: func(in *Input) (*Route, Result) {
		switch {
		case len(in.Bytes()) < 4:
			return nil, NeedMore
		case string(in.Bytes()[:4]) == "SELF":
			return nil, Match
		case string(in.Bytes()[:4]) == "GONE":
			return closed, Match
		case string(in.Bytes()[:4]) == "FORE":
			return foreign, Match
		}
		return nil, Result(42) // an unknown result counts as NoMatch
	}})
	rest := m.Match(Any())
	serve(t, m)

	_, _ = dial(t, m).Write([]byte("SELF"))
	accept(t, self)
	_, _ = dial(t, m).Write([]byte("ELSE"))
	accept(t, rest)
	for data, want := range map[string]error{"GONE": ErrRouteClosed, "FORE": errForeignRoute} {
		c := dial(t, m)
		_, _ = c.Write([]byte(data))
		expectClosed(t, c)
		if err := log.wait(t); !errors.Is(err, want) {
			t.Fatalf("%s: reported %v, want %v", data, err, want)
		}
	}

	for _, cfg := range []RouteConfig{
		{Resolve: self.resolve, Reject: true},
		{Resolve: self.resolve, Fallback: true},
	} {
		if _, err := m.Add(cfg); !errors.Is(err, errResolveConfig) {
			t.Errorf("Add = %v", err)
		}
	}
}

func TestInputPeerAddr(t *testing.T) {
	type addrs struct{ remote, peer string }
	seen := make(chan addrs, 1)
	m := startMux(t, WithProxyProtocol(func(_ string, _, _ net.Addr) proxyproto.Policy { return proxyproto.Required }))
	target := m.Match()
	mustAdd(t, m, RouteConfig{Resolve: func(in *Input) (*Route, Result) {
		select {
		case seen <- addrs{in.RemoteAddr().String(), in.PeerAddr().String()}:
		default:
		}
		return target, Match
	}})
	serve(t, m)
	c := dial(t, m)
	_, _ = c.Write([]byte("PROXY TCP4 192.0.2.1 198.51.100.2 40000 443\r\nx"))
	accept(t, target)
	got := <-seen
	if got.remote != "192.0.2.1:40000" || got.peer != c.LocalAddr().String() {
		t.Fatalf("addresses %+v", got)
	}
}

// BenchmarkResolverHosts routes by Host through a resolver and a map: the
// cost does not grow with the number of targets.
func BenchmarkResolverHosts(b *testing.B) {
	for _, n := range []int{10, 1000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			var domains domainTable
			for i := range n {
				domains.set(fmt.Sprintf("h%d.example.com", i), &Route{name: fmt.Sprint(i)})
			}
			t := newTable(routeSet{routes: map[*Route]routeState{{resolve: domains.resolve}: {}}})
			data := []byte(fmt.Sprintf("GET /api HTTP/1.1\r\nHost: h%d.example.com:443\r\nUser-Agent: x\r\n\r\n", n-1))
			dead := make([]bool, 1)
			b.ReportAllocs()
			for b.Loop() {
				in := &Input{data: data}
				dead[0] = false
				if r, _, res := t.other.evaluate(dead, in); res != Match || r == nil {
					b.Fatal(res)
				}
			}
		})
	}
}

// TestResolverIsOrderedWithRules checks that a resolver is one rule among the
// others: priorities decide whether it is asked before or after them, and its
// matchers are conditions checked before it.
func TestResolverIsOrderedWithRules(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	add := func(cfg RouteConfig) *Route {
		r, err := m.Add(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	var domains domainTable
	targetA := add(RouteConfig{Name: "target-a"})
	targetB := add(RouteConfig{Name: "target-b"})
	domains.set("a.example.com", targetA)
	domains.set("b.example.com", targetB)

	routes := map[string]*Route{"target-a": targetA, "target-b": targetB}
	routes["pinned"] = add(RouteConfig{Name: "pinned", Priority: 20, Matchers: []Matcher{HTTP1(Host("a.example.com"))}})
	add(RouteConfig{Name: "block", Priority: 100, Reject: true, Matchers: []Matcher{RemoteIP(netip.MustParsePrefix("203.0.113.0/24"))}})
	// Asked only for TLS or HTTP from the office.
	resolver := add(RouteConfig{
		Name:     "domains",
		Priority: 10,
		Matchers: []Matcher{And(RemoteIP(netip.MustParsePrefix("10.0.0.0/8")), Or(TLS(), HTTP1()))},
		Resolve:  domains.resolve,
	})
	routes["web"] = add(RouteConfig{Name: "web", Matchers: []Matcher{HTTP1()}})
	got := collect(routes)
	request := func(host string) string { return "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n" }

	tests := []struct{ name, remote, data, want string }{
		{"higher rule first", "10.0.0.1:1", request("a.example.com"), "pinned"},
		{"resolver before lower rules", "10.0.0.1:1", request("b.example.com"), "target-b"},
		{"unknown name to the next rule", "10.0.0.1:1", request("c.example.com"), "web"},
		{"condition not met: resolver skipped", "192.0.2.1:1", request("b.example.com"), "web"},
		{"block list above all", "203.0.113.5:1", request("b.example.com"), ErrRefused.Error()},
	}
	for _, tt := range tests {
		if name := routeOf(t, m, got, tt.remote, tt.data); name != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, name, tt.want)
		}
	}

	// Moving the resolver above the pinned rule changes who answers first.
	if err := resolver.SetPriority(30); err != nil {
		t.Fatal(err)
	}
	if name := routeOf(t, m, got, "10.0.0.1:1", request("a.example.com")); name != "target-a" {
		t.Errorf("after raising the resolver: %q", name)
	}
	// Its conditions can change too.
	if err := resolver.SetMatchers(Or(TLS(), HTTP1())); err != nil {
		t.Fatal(err)
	}
	if name := routeOf(t, m, got, "192.0.2.1:1", request("b.example.com")); name != "target-b" {
		t.Errorf("after widening the conditions: %q", name)
	}
	var order []string
	for _, info := range m.Snapshot().Routes {
		order = append(order, info.Name)
	}
	if want := []string{"block", "domains", "pinned", "target-a", "target-b", "web"}; !slices.Equal(order, want) {
		t.Errorf("order %q, want %q", order, want)
	}
	if info := resolver.Info(); !info.Resolver || len(info.Matchers) != 1 || info.Matchers[0] != "Or(TLS(), HTTP1())" {
		t.Errorf("info %+v", info)
	}
}

func TestResolveDomain(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	var hosts hostmatch.Map[*Route]
	resolver, err := m.Add(RouteConfig{Name: "domains", Resolve: ResolveDomain(&hosts)})
	if err != nil {
		t.Fatal(err)
	}
	site, _ := m.Add(RouteConfig{Name: "site"})
	wild, _ := m.Add(RouteConfig{Name: "wild"})
	rest := m.Match(Any())
	hosts.Set("www.example.com", site)
	hosts.Set("*.example.com", wild)
	hosts.Set("self.example.com", nil)
	routes := map[string]*Route{"site": site, "wild": wild, "domains": resolver, "rest": rest}
	got := collect(routes)
	request := func(host string) string { return "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n" }
	hello := func(name string) string {
		return string(testutil.HelloRecord(testutil.Ext(tlshello.ExtensionServerName, testutil.U16List(testutil.SNIEntry(0, name)))))
	}

	for data, want := range map[string]string{
		request("www.example.com:8080"): "site",
		request("www.example.com.."):    "rest", // one trailing dot is ignored, as by Domain
		request("a.b.example.com"):      "wild",
		request("self.example.com"):     "domains",
		request("example.org"):          "rest",
		hello("WWW.example.com"):        "site",
		hello("x.example.com"):          "wild",
		"SSH-2.0-x\r\n":                 "rest",
	} {
		if name := routeOf(t, m, got, "192.0.2.1:1", data); name != want {
			t.Errorf("%q: %s, want %s", data[:12], name, want)
		}
	}
	hosts.Delete("*.example.com")
	if name := routeOf(t, m, got, "192.0.2.1:1", request("a.example.com")); name != "rest" {
		t.Errorf("after Delete: %s", name)
	}
	if !slices.Contains(m.Routes(), resolver) {
		t.Fatal("resolver missing")
	}
}

func TestRequestedName(t *testing.T) {
	hello := testutil.HelloRecord(testutil.Ext(tlshello.ExtensionServerName, testutil.U16List(testutil.SNIEntry(0, "API.example.com"))))
	for data, want := range map[string]struct {
		name string
		res  Result
	}{
		string(hello):                                    {"api.example.com", Match},
		string(testutil.HelloRecord(nil)):                {"", Match},
		"GET / HTTP/1.1\r\nHost: H.example:8080\r\n\r\n": {"h.example", Match},
		"GET / HTTP/1.1\r\nHost: a@b\r\n\r\n":            {"", NoMatch},
		"GET / HTTP/1.1\r\n":                             {"", NeedMore},
		"SSH-2.0-x\r\n":                                  {"", NoMatch},
	} {
		if name, res := inputOf([]byte(data)).RequestedName(); name != want.name || res != want.res {
			t.Errorf("%q: %q, %v; want %q, %v", data[:min(len(data), 16)], name, res, want.name, want.res)
		}
	}
}

// TestResolveHosts keeps a TLS and an HTTP target per name and falls back to
// wider patterns when a name has no target for the protocol.
func TestResolveHosts(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	type site struct{ tls, http *Route }
	add := func(name string) *Route {
		r, err := m.Add(RouteConfig{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	exactTLS, wildTLS, wildHTTP := add("exact-tls"), add("wild-tls"), add("wild-http")
	var sites hostmatch.Map[site]
	sites.Set("www.example.com", site{tls: exactTLS})
	sites.Set("*.example.com", site{tls: wildTLS, http: wildHTTP})
	sites.Set("self.example.com", site{tls: nil, http: nil})
	var picked []string
	resolver, err := m.Add(RouteConfig{Name: "sites", Resolve: ResolveHosts(&sites, func(in *Input, pattern string, s site) (*Route, bool) {
		picked = append(picked, pattern)
		if pattern == "self.example.com" {
			return nil, true
		}
		if _, res := in.ClientHello(); res == Match {
			return s.tls, s.tls != nil
		}
		return s.http, s.http != nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	rest := m.Match(Any())
	got := collect(map[string]*Route{"exact-tls": exactTLS, "wild-tls": wildTLS, "wild-http": wildHTTP, "sites": resolver, "rest": rest})
	request := func(host string) string { return "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n" }
	hello := func(name string) string {
		return string(testutil.HelloRecord(testutil.Ext(tlshello.ExtensionServerName, testutil.U16List(testutil.SNIEntry(0, name)))))
	}

	tests := []struct {
		data, want string
		picked     []string
	}{
		{hello("www.example.com"), "exact-tls", []string{"www.example.com"}},
		// www has no HTTP target: the wider pattern takes it.
		{request("www.example.com"), "wild-http", []string{"www.example.com", "*.example.com"}},
		{hello("a.example.com"), "wild-tls", []string{"*.example.com"}},
		{request("self.example.com"), "sites", []string{"self.example.com"}},
		{request("other.org"), "rest", nil},
	}
	for _, tt := range tests {
		picked = nil
		if name := routeOf(t, m, got, "192.0.2.1:1", tt.data); name != tt.want || !slices.Equal(picked, tt.picked) {
			t.Errorf("%q: %s after %q, want %s after %q", tt.data[:min(len(tt.data), 20)], name, picked, tt.want, tt.picked)
		}
	}
}

//goland:noinspection HttpUrlsUsage
func TestDomainMatchesH2C(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://www.example.com/", nil)
	data := testutil.H2CBytes(t, req)
	if Domain("*.example.com").Match(inputOf(data)) != Match || Domain("other.org").Match(inputOf(data)) != NoMatch {
		t.Fatal("Domain on h2c")
	}
	var hosts hostmatch.Map[*Route]
	target := &Route{name: "t"}
	hosts.Set("www.example.com", target)
	if r, res := ResolveDomain(&hosts)(inputOf(data)); res != Match || r != target {
		t.Fatalf("ResolveDomain = %v, %v", r, res)
	}
}

// TestRoutingByDomain routes HTTP and TLS by domain with exclusions, and checks
// that excluded names fall through to the next route instead of matching
// other protocols.
func TestRoutingByDomain(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	routes := map[string]*Route{
		"admin":  m.Match(HTTP1(Host("admin.example.com")), TLS(SNI("admin.example.com"))),
		"public": m.Match(HTTP1(Host("*.example.com"), NoneOf(Host("admin.example.com"), PathPrefix("/internal/")))),
		"api":    m.Match(TLS(AllOf(SNI("*.example.com"), NoneOf(SNI("admin.example.com"))), AnyOf(ALPN("h2"), SNI("legacy.example.com")))),
		"other":  m.Match(HTTP1(), TLS()),
	}
	got := collect(routes)
	request := func(host, path string) string {
		return "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	}
	hello := func(sni string, alpn ...string) string {
		return string(testutil.ClientHelloBytes(t, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true}))
	}
	tests := []struct{ name, data, want string }{
		{"public site", request("www.example.com", "/"), "public"},
		{"excluded host", request("admin.example.com", "/"), "admin"},
		{"excluded path", request("www.example.com", "/internal/x"), "other"},
		{"other domain", request("www.other.org", "/"), "other"},
		{"api over h2", hello("api.example.com", "h2"), "api"},
		{"legacy without h2", hello("legacy.example.com", "http/1.1"), "api"},
		{"api without h2", hello("api.example.com", "http/1.1"), "other"},
		{"admin over TLS", hello("admin.example.com", "h2"), "admin"},
	}
	for _, tt := range tests {
		if name := routeOf(t, m, got, "192.0.2.1:1000", tt.data); name != tt.want {
			t.Errorf("%s: routed to %q, want %q", tt.name, name, tt.want)
		}
	}
}

func TestDomainMatcher(t *testing.T) {
	m := Domain("*.example.com", "example.com")
	if describe(m) != `Domain("*.example.com", "example.com")` {
		t.Fatalf("description %s", describe(m))
	}
	check := func(data string, final bool, want Result) {
		t.Helper()
		in := NewInput(nil, nil)
		in.SetBytes([]byte(data), final)
		if got := m.Match(in); got != want {
			t.Errorf("%q: %v, want %v", data, got, want)
		}
	}
	check("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n", false, Match)
	check("GET / HTTP/1.1\r\nHost: www.example.org\r\n\r\n", false, NoMatch)
	check(string(testutil.ClientHelloBytes(t, &tls.Config{ServerName: "Example.com", InsecureSkipVerify: true})), false, Match)
	check("GET / HTTP/1.1\r\n", false, NeedMore)
	check("\x16\x03", false, NeedMore)
	check("SSH-2.0-OpenSSH_9.6\r\n", false, NoMatch)
}
