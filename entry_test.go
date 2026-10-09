package portmux

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/internal/testutil"
)

// listen returns a loopback listener served as entry e of m.
func listen(t *testing.T, e *Entry) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = e.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func dialTo(t *testing.T, ln net.Listener, data string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if data != "" {
		if _, err := c.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// TestEntriesSeparateListenersAndServices sets listeners up apart from the
// services: each service picks the entries it is offered on.
func TestEntriesSeparateListenersAndServices(t *testing.T) {
	m := New()
	t.Cleanup(func() { _ = m.Close() })
	add := func(cfg RouteConfig) *Route {
		r, err := m.Add(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Services and their rules.
	siteA := add(RouteConfig{Name: "site-a", Entries: []string{"http", "https"}, Matchers: []Matcher{Domain("a.example.com")}})
	siteB := add(RouteConfig{Name: "site-b", Entries: []string{"https"}, Matchers: []Matcher{Domain("b.example.com")}})
	httpDefault := add(RouteConfig{Name: "http-default", Entries: []string{"http"}, Fallback: true})
	httpsDefault := add(RouteConfig{Name: "https-default", Entries: []string{"https"}, Fallback: true})
	tunnel := add(RouteConfig{Name: "tunnel-9000", Entries: []string{"tcp-9000"}, Matchers: []Matcher{Always()}})
	// Listeners: two for the http entry, one each for the others.
	http1 := listen(t, m.Entry("http"))
	http2 := listen(t, m.Entry("http"))
	https := listen(t, m.Entry("https"))
	dedicated := listen(t, m.Entry("tcp-9000"))
	waitServing(t, m, 4)

	request := func(host string) string { return "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n" }
	hello := func(name string) string {
		return string(testutil.ClientHelloBytes(t, &tls.Config{ServerName: name, InsecureSkipVerify: true}))
	}

	_ = dialTo(t, http1, request("a.example.com"))
	if got := accept(t, siteA); got.Entry() != "http" {
		t.Fatalf("entry %q", got.Entry())
	}
	_ = dialTo(t, https, hello("a.example.com"))
	if got := accept(t, siteA); got.Entry() != "https" || got.ClientHello().ServerName != "a.example.com" {
		t.Fatalf("entry %q", got.Entry())
	}
	// site-b is not offered on http: the http entry's fallback takes it.
	_ = dialTo(t, http2, request("b.example.com"))
	accept(t, httpDefault)
	_ = dialTo(t, https, hello("b.example.com"))
	accept(t, siteB)
	_ = dialTo(t, https, hello("c.example.com"))
	accept(t, httpsDefault)

	// Offering site-b on http too is one change to the service.
	if err := siteB.SetEntries("http", "https"); err != nil {
		t.Fatal(err)
	}
	_ = dialTo(t, http1, request("b.example.com"))
	accept(t, siteB)

	// The dedicated port hands connections over at once: the server speaks
	// first, and nothing was read from the client.
	c := dialTo(t, dedicated, "")
	got := accept(t, tunnel)
	if got.Unread() != nil || got.Entry() != "tcp-9000" {
		t.Fatalf("unread %q, entry %q", got.Unread(), got.Entry())
	}
	_, _ = got.Write([]byte("220 ready\r\n"))
	if b := readN(t, c, 5); string(b) != "220 r" {
		t.Fatalf("banner %q", b)
	}

	// A route's address lists the listeners of its entries.
	if got := tunnel.Addr().String(); got != dedicated.Addr().String() {
		t.Fatalf("tunnel address %s", got)
	}
	if got := strings.Split(siteB.Addr().String(), ","); len(got) != 3 || slices.Contains(got, dedicated.Addr().String()) {
		t.Fatalf("site-b addresses %q", got)
	}

	snap := m.Snapshot()
	var entries []string
	for _, l := range snap.Listeners {
		entries = append(entries, l.Entry)
	}
	if !slices.Equal(entries, []string{"http", "http", "https", "tcp-9000"}) {
		t.Fatalf("listener entries %q", entries)
	}
	for _, info := range snap.Routes {
		if info.Name == "site-b" && !slices.Equal(info.Entries, []string{"http", "https"}) {
			t.Fatalf("site-b entries %q", info.Entries)
		}
		if info.Fallback && !info.Active {
			t.Fatalf("%s inactive", info.Name)
		}
	}
}

func TestEntryRulesApplyAcrossEntries(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	block, err := m.Add(RouteConfig{Name: "block", Priority: 100, Reject: true,
		Matchers: []Matcher{RemoteIP(netip.MustParsePrefix("203.0.113.0/24"))}})
	if err != nil {
		t.Fatal(err)
	}
	// Rules of other entries are not even asked.
	var asked atomic.Int64
	counting := MatcherFunc(func(*Input) Result {
		asked.Add(1)
		return NoMatch
	})
	if _, err := m.Add(RouteConfig{Entries: []string{"admin"}, Matchers: []Matcher{counting}}); err != nil {
		t.Fatal(err)
	}
	public, err := m.Add(RouteConfig{Name: "public", Entries: []string{"public"}, Matchers: []Matcher{Any()}})
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]*Route{"public": public}
	got := collect(routes)

	serve := func(entry, remote string) string {
		client, server := net.Pipe()
		defer func() { _ = client.Close() }()
		go func() { _, _ = client.Write([]byte("x")) }()
		c := &addrConn{Conn: server, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote)), local: memLocal}
		if err := m.Entry(entry).ServeConn(c); err != nil {
			return err.Error()
		}
		select {
		case name := <-got:
			return name
		case <-time.After(5 * time.Second):
			t.Fatal("not delivered")
			return ""
		}
	}
	if got := serve("public", "203.0.113.9:1"); got != ErrRefused.Error() {
		t.Fatalf("blocked client on public: %s", got)
	}
	if got := serve("public", "192.0.2.1:1"); got != "public" {
		t.Fatalf("public: %s", got)
	}
	if got := serve("elsewhere", "192.0.2.1:1"); got != ErrNoMatch.Error() {
		t.Fatalf("unknown entry: %s", got)
	}
	if asked.Load() != 0 {
		t.Fatalf("a rule of the admin entry was asked %d times", asked.Load())
	}
	if block.Matched() != 1 {
		t.Fatalf("block matched %d", block.Matched())
	}
}

// TestEntryIgnoresProxyAddresses routes by entry behind a load balancer,
// where the local address from the PROXY header names the balancer's port,
// and expects headers on that entry only.
func TestEntryIgnoresProxyAddresses(t *testing.T) {
	m := New(WithProxyProtocol(func(entry string, _, _ net.Addr) proxyproto.Policy {
		if entry == "lb" {
			return proxyproto.Required
		}
		return proxyproto.Ignore
	}))
	t.Cleanup(func() { _ = m.Close() })
	direct, err := m.Add(RouteConfig{Entries: []string{"direct"}, Matchers: []Matcher{Prefix("PROXY ")}})
	if err != nil {
		t.Fatal(err)
	}
	var seen atomic.Value
	lb, err := m.Add(RouteConfig{Name: "lb", Entries: []string{"lb"}, Resolve: func(in *Input) (*Route, Result) {
		seen.Store(in.Entry() + " " + in.LocalAddr().String())
		return nil, Match
	}})
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t, m.Entry("lb"))
	other := listen(t, m.Entry("direct"))
	waitServing(t, m, 2)
	header := "PROXY TCP4 192.0.2.1 198.51.100.2 40000 443\r\n"
	_ = dialTo(t, ln, header+"hello")
	got := accept(t, lb)
	if seen.Load() != "lb 198.51.100.2:443" || got.Entry() != "lb" || got.LocalAddr().String() != "198.51.100.2:443" {
		t.Fatalf("seen %v, entry %q", seen.Load(), got.Entry())
	}
	// Other entries take the header as data.
	_ = dialTo(t, other, header)
	if got := accept(t, direct); got.ProxyHeader() != nil || string(got.Unread()) != header {
		t.Fatalf("header %+v, unread %q", got.ProxyHeader(), got.Unread())
	}
}

func TestAlwaysTakesNoBuffer(t *testing.T) {
	var taken atomic.Int64
	count := func() { taken.Add(1) }
	bufferTaken.Store(&count)
	defer bufferTaken.Store(nil)

	m := New()
	defer func() { _ = m.Close() }()
	r := m.Match(Always())
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() { _ = m.ServeConn(server) }()
	got := accept(t, r)
	if taken.Load() != 0 || got.Unread() != nil {
		t.Fatalf("buffers %d, unread %q", taken.Load(), got.Unread())
	}
	go func() { _, _ = client.Write([]byte("later")) }()
	if b, err := io.ReadAll(io.LimitReader(got, 5)); err != nil || string(b) != "later" {
		t.Fatalf("read %q, %v", b, err)
	}
	in := NewInput(nil, nil)
	in.SetEntry("x")
	if Always().Match(in) != Match || in.Entry() != "x" || describe(Always()) != "Always()" {
		t.Fatal("Always on an Input")
	}
}

// TestEntryOptions gives entries settings of their own on top of the Mux's.
func TestEntryOptions(t *testing.T) {
	type report struct {
		entry string
		err   error
	}
	reports := make(chan report, 16)
	m := New(WithMaxPending(100), WithBanPerIP(1, time.Minute, time.Minute), WithObserver(func(ev Event) {
		if ev.Err != nil {
			reports <- report{ev.Entry, ev.Err}
		}
	}))
	t.Cleanup(func() { _ = m.Close() })
	web, err := m.Add(RouteConfig{Matchers: []Matcher{Prefix("GET")}})
	if err != nil {
		t.Fatal(err)
	}
	expect := func(entry string, want error) {
		t.Helper()
		select {
		case r := <-reports:
			if r.entry != entry || !errors.Is(r.err, want) {
				t.Fatalf("reported %+v, want %v on %s", r, want, entry)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no report on %s", entry)
		}
	}
	public, internal := m.Entry("public"), m.Entry("internal")
	public.SetOptions(WithSniffTimeout(50*time.Millisecond), WithRateLimitPerIP(0.001, 2), WithBanPerIP(0, 0, 0))
	internal.SetOptions(WithBanPerIP(0, 0, 0))
	pub, in := listen(t, public), listen(t, internal)
	waitServing(t, m, 2)

	// The short sniff timeout of the public entry; the internal one waits.
	// Neither entry bans yet, although the Mux bans at the first failure.
	c := dialTo(t, pub, "")
	expectClosed(t, c)
	expect("public", ErrSniffTimeout)
	c = dialTo(t, in, "GE")
	time.Sleep(100 * time.Millisecond)
	if web.Matched() != 0 || m.Stats().Pending != 1 {
		t.Fatalf("matched %d, stats %+v", web.Matched(), m.Stats())
	}
	_, _ = c.Write([]byte("T"))
	accept(t, web)

	// Failures on the internal entry do not ban, and its rate is the Mux's.
	_ = dialTo(t, in, "XX")
	expect("internal", ErrNoMatch)
	_ = dialTo(t, in, "GET")
	accept(t, web)
	// The public entry has buckets of its own: the timed-out connection took
	// the first token, this one the second, the next none.
	_ = dialTo(t, pub, "GET")
	accept(t, web)
	c = dialTo(t, pub, "GET")
	expectClosed(t, c)
	expect("public", ErrRateLimited)

	// Settings read back, with the entry's on top of the Mux's.
	if got := m.Config(); got.SniffTimeout != DefaultSniffTimeout || got.BanFailures != 1 || got.MaxPending != 100 || !got.Observer {
		t.Fatalf("Mux config %+v", got)
	}
	got := public.Config()
	if got.SniffTimeout != 50*time.Millisecond || got.RateLimitPerIP != 0.001 || got.RateBurstPerIP != 2 || got.BanFailures != 0 || got.MaxPending != 100 {
		t.Fatalf("public config %+v", got)
	}
	// A change to the Mux applies to what the entry does not override, and
	// the entry keeps its buckets.
	m.SetOptions(WithSniffTimeout(time.Minute), WithMaxSniffBytes(512))
	if got := public.Config(); got.SniffTimeout != 50*time.Millisecond || got.MaxSniffBytes != 512 {
		t.Fatalf("public config after Mux change %+v", got)
	}
	c = dialTo(t, pub, "GET")
	expectClosed(t, c)
	expect("public", ErrRateLimited)

	// Reset, the entry follows the Mux again.
	public.ResetOptions()
	if got, want := public.Config(), m.Config(); got != want {
		t.Fatalf("after reset %+v, want %+v", got, want)
	}
	_ = dialTo(t, pub, "GET")
	accept(t, web)
	// A failure on the public entry bans the client on every entry.
	_ = dialTo(t, pub, "XX")
	expect("public", ErrNoMatch)
	c = dialTo(t, in, "GET")
	expectClosed(t, c)
	expect("internal", ErrBanned)
}

// TestEntryOwnRateBuckets gives an entry a per-client rate of its own, equal
// to the Mux's: the entry keeps buckets apart, also when the Mux's rate
// changes.
func TestEntryOwnRateBuckets(t *testing.T) {
	log := newErrorLog()
	m := New(WithRateLimitPerIP(0.001, 1), log.option())
	t.Cleanup(func() { _ = m.Close() })
	web, err := m.Add(RouteConfig{Matchers: []Matcher{Prefix("GET")}})
	if err != nil {
		t.Fatal(err)
	}
	own := m.Entry("own")
	own.SetOptions(WithRateLimitPerIP(0.001, 1))
	def, ln := listen(t, m.Entry("")), listen(t, own)
	waitServing(t, m, 2)

	_ = dialTo(t, def, "GET")
	accept(t, web)
	// The Mux's bucket of the client is empty, the entry's is not.
	_ = dialTo(t, ln, "GET")
	accept(t, web)
	for _, rate := range []float64{0.002, 0.001} {
		m.SetOptions(WithRateLimitPerIP(rate, 1))
		expectClosed(t, dialTo(t, ln, "GET"))
		if err := log.wait(t); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("after the Mux's rate became %v: %v", rate, err)
		}
	}
}
