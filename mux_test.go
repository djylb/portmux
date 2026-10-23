package portmux

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/internal/testutil"
)

func TestPrefixRouteReplaysBytes(t *testing.T) {
	m := startMux(t)
	bridge := m.Listen(Prefix("TST"))
	serve(t, m)

	c := dial(t, m)
	if _, err := c.Write([]byte("TSThello")); err != nil {
		t.Fatal(err)
	}
	got := accept(t, bridge)
	if b := readN(t, got, 8); string(b) != "TSThello" {
		t.Fatalf("read %q", b)
	}
	if got.ClientHello() != nil || got.HTTPRequest() != nil || got.ProxyHeader() != nil {
		t.Fatal("unexpected parsed metadata")
	}
	if _, err := got.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if b := readN(t, c, 2); string(b) != "ok" {
		t.Fatalf("reply %q", b)
	}
	if got.RemoteAddr().String() != c.LocalAddr().String() || got.LocalAddr().String() != c.RemoteAddr().String() {
		t.Fatalf("addresses %v %v", got.RemoteAddr(), got.LocalAddr())
	}
	if _, ok := got.NetConn().(*net.TCPConn); !ok {
		t.Fatalf("NetConn = %T", got.NetConn())
	}
}

// serveTLSNames completes a TLS handshake on every connection from l, then
// sends name and the negotiated protocol and closes the connection.
func serveTLSNames(t *testing.T, l net.Listener, name string) {
	cfg := &tls.Config{Certificates: []tls.Certificate{certificate(t)}, NextProtos: []string{"h2", "http/1.1"}}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				tc := tls.Server(c, cfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				_, _ = fmt.Fprintf(tc, "%s|%s|%s", name, tc.ConnectionState().ServerName, c.(*Conn).ClientHello().ServerName)
			}()
		}
	}()
}

func tlsRequest(t *testing.T, m *testMux, serverName string, alpn ...string) string {
	t.Helper()
	tc := tls.Client(dial(t, m), &tls.Config{ServerName: serverName, NextProtos: alpn, InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(tc)
	if err != nil {
		t.Fatalf("TLS to %q: %v", serverName, err)
	}
	return string(b)
}

func TestTLSRoutingBySNIAndALPN(t *testing.T) {
	m := startMux(t)
	serveTLSNames(t, m.Listen(TLS(SNI("admin.example.com"))), "admin")
	serveTLSNames(t, m.Listen(TLS(ALPN("h2"))), "h2")
	serveTLSNames(t, m.Listen(TLS(SNI("*.example.com"))), "wild")
	serveTLSNames(t, m.Listen(TLS()), "default")
	serve(t, m)

	tests := []struct {
		sni  string
		alpn []string
		want string
	}{
		{"admin.example.com", []string{"h2"}, "admin|admin.example.com|admin.example.com"},
		{"x.example.com", []string{"h2"}, "h2|x.example.com|x.example.com"},
		{"x.example.com", nil, "wild|x.example.com|x.example.com"},
		{"localhost", nil, "default|localhost|localhost"},
		{"", nil, "default||"},
	}
	for _, tt := range tests {
		if got := tlsRequest(t, m, tt.sni, tt.alpn...); got != tt.want {
			t.Errorf("sni %q alpn %q: got %q, want %q", tt.sni, tt.alpn, got, tt.want)
		}
	}
}

func httpServer(t *testing.T, l net.Listener, name string) {
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s %s %s", name, r.Host, r.URL.Path)
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
}

//goland:noinspection HttpUrlsUsage
func TestHTTPServersOnRoutes(t *testing.T) {
	m := startMux(t)
	httpServer(t, m.Listen(HTTP1(Host("api.example.com"), PathPrefix("/v1/"))), "api")
	httpServer(t, m.Listen(HTTP1()), "web")
	serve(t, m)

	client := &http.Client{Transport: &http.Transport{}}
	t.Cleanup(client.CloseIdleConnections)
	get := func(host, path string) string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "http://"+m.Addr().String()+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := get("api.example.com:8080", "/v1/users"); got != "api api.example.com:8080 /v1/users" {
		t.Errorf("got %q", got)
	}
	// A keep-alive request reuses the routed connection.
	if got := get("api.example.com:8080", "/v1/again"); got != "api api.example.com:8080 /v1/again" {
		t.Errorf("got %q", got)
	}
	// Routing is per connection: a request for another host needs a new one.
	client.CloseIdleConnections()
	if got := get("www.example.com", "/v1/users"); got != "web www.example.com /v1/users" {
		t.Errorf("got %q", got)
	}
}

func TestEarlierRouteWaitsForMoreBytes(t *testing.T) {
	m := startMux(t)
	specific := m.Listen(HTTP1(Host("a.example")))
	general := m.Listen(Prefix("GET "))
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n"))
	// Delivering to the general route now would leave specific without it.
	time.Sleep(50 * time.Millisecond)
	_, _ = c.Write([]byte("Host: a.example\r\n\r\n"))
	got := accept(t, specific)
	if got.HTTPRequest() == nil || got.HTTPRequest().Host != "a.example" {
		t.Fatalf("request = %+v", got.HTTPRequest())
	}

	c2 := dial(t, m)
	_, _ = c2.Write([]byte("GET / HTTP/1.1\r\nHost: b.example\r\n\r\n"))
	got2 := accept(t, general)
	if b := readN(t, got2, 4); string(b) != "GET " {
		t.Fatalf("read %q", b)
	}
	if got2.HTTPRequest() == nil {
		t.Fatal("request parsed by the earlier route is not attached")
	}
}

func TestClientHelloByteByByte(t *testing.T) {
	m := startMux(t)
	tlsRoute := m.Listen(TLS(SNI("slow.example.com")))
	serve(t, m)

	hello := testutil.ClientHelloBytes(t, &tls.Config{ServerName: "slow.example.com", InsecureSkipVerify: true})
	c := dial(t, m)
	go func() {
		for i := range hello {
			if _, err := c.Write(hello[i : i+1]); err != nil {
				return
			}
		}
	}()
	got := accept(t, tlsRoute)
	if b := readN(t, got, len(hello)); !bytes.Equal(b, hello) {
		t.Fatal("replayed bytes differ")
	}
}

func TestFinalInputOnHalfClose(t *testing.T) {
	m := startMux(t)
	bridge := m.Listen(Prefix("TST"))
	rest := m.Listen(AnyBytes())
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("TS"))
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := accept(t, rest)
	b, err := io.ReadAll(got)
	if err != nil || string(b) != "TS" {
		t.Fatalf("ReadAll = %q, %v", b, err)
	}
	expectNoAccept(t, bridge, 20*time.Millisecond)
}

func TestNoMatchClosesConnection(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	m.Listen(Prefix("TST"))
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("XYZ"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("reported %v, want ErrNoMatch", err)
	}
}

func TestEmptyConnectionReportsEOF(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	m.Listen(AnyBytes())
	serve(t, m)

	_ = dial(t, m).Close()
	if err := log.wait(t); !errors.Is(err, io.EOF) {
		t.Fatalf("reported %v, want io.EOF", err)
	}
}

func TestSniffTimeout(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithSniffTimeout(100*time.Millisecond))
	m.Listen(Prefix("TST"))
	serve(t, m)

	for _, data := range []string{"", "TS"} {
		c := dial(t, m)
		_, _ = c.Write([]byte(data))
		expectClosed(t, c)
		err := log.wait(t)
		var ne net.Error
		if !errors.Is(err, ErrSniffTimeout) || !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("data %q: reported %v, want ErrSniffTimeout wrapping a timeout", data, err)
		}
	}
}

func TestMaxSniffBytes(t *testing.T) {
	m := startMux(t, WithMaxSniffBytes(64))
	hosted := m.Listen(HTTP1(Host("a.example")))
	rest := m.Listen(AnyBytes())
	serve(t, m)

	req := "GET / HTTP/1.1\r\nX-Pad: " + strings.Repeat("p", 200) + "\r\nHost: a.example\r\n\r\n"
	c := dial(t, m)
	_, _ = c.Write([]byte(req))
	got := accept(t, rest)
	if b := readN(t, got, len(req)); string(b) != req {
		t.Fatalf("read %q", b)
	}
	if got.HTTPRequest() != nil {
		t.Fatal("request parsed beyond the sniff limit")
	}
	expectNoAccept(t, hosted, 20*time.Millisecond)
}

func TestDispatchTimeout(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithDispatchTimeout(50*time.Millisecond))
	m.Listen(Prefix("A"))
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("A"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrDispatchTimeout) {
		t.Fatalf("reported %v, want ErrDispatchTimeout", err)
	}
}

func TestRouteClose(t *testing.T) {
	m := startMux(t)
	first := m.Listen(Prefix("A"))
	rest := m.Listen(AnyBytes())
	serve(t, m)

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v", err)
	}
	if first.Addr().String() != m.Addr().String() {
		t.Fatalf("Addr = %v", first.Addr())
	}
	c := dial(t, m)
	_, _ = c.Write([]byte("A"))
	if b := readN(t, accept(t, rest), 1); string(b) != "A" {
		t.Fatalf("read %q", b)
	}
}

func TestRouteClosedWhileDispatchingRematches(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	route := m.Listen(Prefix("A"))
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("A"))
	time.Sleep(50 * time.Millisecond)
	_ = route.Close()
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("reported %v, want ErrNoMatch", err)
	}
}

func TestMatchWhileServing(t *testing.T) {
	m := startMux(t)
	serve(t, m)
	late := m.Listen(Prefix("L"))

	c := dial(t, m)
	_, _ = c.Write([]byte("L"))
	accept(t, late)
}

func TestCloseStopsEverything(t *testing.T) {
	m := startMux(t, WithSniffTimeout(-1))
	route := m.Listen(Prefix("A"))
	errc := make(chan error, 1)
	go func() { errc <- m.Serve(m.ln) }()
	waitServing(t, m.Mux, 1)

	silent := dial(t, m)
	time.Sleep(50 * time.Millisecond)
	accepted := make(chan error, 1)
	go func() {
		_, err := route.Accept()
		accepted <- err
	}()

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	for name, ch := range map[string]chan error{"Serve": errc, "Accept": accepted} {
		select {
		case err := <-ch:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("%s returned %v, want net.ErrClosed", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not return", name)
		}
	}
	expectClosed(t, silent)
	if _, err := m.Listen(AnyBytes()).Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept on a route added after Close = %v", err)
	}
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Serve(other); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve after Close = %v", err)
	}
	if _, err := net.Dial("tcp", other.Addr().String()); err == nil {
		t.Fatal("Serve after Close left the listener open")
	}
	if err := m.ServeConn(&memConn{data: []byte("A")}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ServeConn after Close = %v", err)
	}
}

func TestServeSeveralListeners(t *testing.T) {
	m := startMux(t)
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstPort := uint16(m.ln.Addr().(*net.TCPAddr).Port)
	viaFirst := m.Listen(LocalPort(firstPort))
	rest := m.Listen(AnyBytes())
	serve(t, m)
	errc := make(chan error, 1)
	go func() { errc <- m.Serve(second) }()
	waitServing(t, m.Mux, 2)

	if got := viaFirst.Addr().String(); !strings.Contains(got, m.ln.Addr().String()) || !strings.Contains(got, second.Addr().String()) {
		t.Fatalf("Addr = %q", got)
	}
	// LocalPort decides before any byte arrives.
	_ = dial(t, m)
	accept(t, viaFirst)
	c, err := net.Dial("tcp", second.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("x"))
	accept(t, rest)

	// Closing one listener stops only its Serve.
	_ = second.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Serve returned nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after its listener closed")
	}
	waitServing(t, m.Mux, 1)
	_ = dial(t, m)
	accept(t, viaFirst)
}

// scriptedListener returns queued errors from Accept before delegating.
type scriptedListener struct {
	net.Listener
	mu   sync.Mutex
	errs []error
	// fail is returned forever once the queue is empty, when set.
	fail error
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, err
	}
	fail := l.fail
	l.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	return l.Listener.Accept()
}

type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary accept failure" }
func (temporaryError) Temporary() bool { return true }
func (temporaryError) Timeout() bool   { return false }

func TestTemporaryAcceptErrorsAreRetried(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log := newErrorLog()
	var addrs []net.Addr
	var mu sync.Mutex
	m := &testMux{ln: &scriptedListener{Listener: ln, errs: []error{temporaryError{}, temporaryError{}}},
		Mux: New(WithObserver(func(ev Event) {
			if ev.Err == nil {
				return
			}
			mu.Lock()
			addrs = append(addrs, ev.Remote)
			mu.Unlock()
			log.ch <- ev.Err
		}))}
	route := m.Listen(AnyBytes())
	serve(t, m)

	for range 2 {
		if err := log.wait(t); !errors.As(err, new(temporaryError)) {
			t.Fatalf("reported %v", err)
		}
	}
	c := dial(t, m)
	_, _ = c.Write([]byte("x"))
	accept(t, route)
	mu.Lock()
	defer mu.Unlock()
	for _, a := range addrs {
		if a != nil {
			t.Fatalf("Accept error reported with address %v", a)
		}
	}
}

func TestListenerFailureStopsOnlyItsServe(t *testing.T) {
	m := startMux(t)
	route := m.Listen(AnyBytes())
	serve(t, m)

	broken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("listener broke")
	if err := m.Serve(&scriptedListener{Listener: broken, fail: boom}); !errors.Is(err, boom) {
		t.Fatalf("Serve = %v", err)
	}
	if _, err := net.Dial("tcp", broken.Addr().String()); err == nil {
		t.Fatal("failed listener still open")
	}
	c := dial(t, m)
	_, _ = c.Write([]byte("x"))
	accept(t, route)
}

// TestMatchedConnectionsFreeTheirSlot checks that a matched connection that
// waits for Accept gives its pending slot to the next one.
func TestMatchedConnectionsFreeTheirSlot(t *testing.T) {
	m := startMux(t, WithMaxPending(1), WithDispatchTimeout(-1))
	stuck := m.Listen(Prefix("A")) // nobody accepts yet
	serve(t, m)

	_, _ = dial(t, m).Write([]byte("A"))
	waitUntil(t, "the first connection is matched", func() bool { return stuck.Matched() == 1 })
	_, _ = dial(t, m).Write([]byte("AB"))
	waitUntil(t, "the second connection is matched", func() bool { return stuck.Matched() == 2 })
	if b := readN(t, accept(t, stuck), 1); string(b) != "A" {
		t.Fatalf("read %q, want the first connection", b)
	}
	if b := readN(t, accept(t, stuck), 2); string(b) != "AB" {
		t.Fatalf("read %q, want the second connection", b)
	}
	if st := m.Stats(); st.Evicted != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// TestNestedRoutesDoNotStarveSlots serves a route of a Mux with the same
// Mux, as nesting a second round of matching inside TLS does, under a small
// pending limit: the inner connections must not wait for slots that outer
// connections waiting for them hold.
func TestNestedRoutesDoNotStarveSlots(t *testing.T) {
	m := startMux(t, WithMaxPending(2), WithDispatchTimeout(-1))
	outer, err := m.Add(RouteConfig{Matchers: []Matcher{Prefix("NN")}, Entries: []string{""}})
	if err != nil {
		t.Fatal(err)
	}
	inner, err := m.Add(RouteConfig{Matchers: []Matcher{Prefix("NN")}, Entries: []string{"inner"}})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, m)
	go func() { _ = m.Entry("inner").Serve(outer) }()

	const clients = 40
	go func() {
		for {
			c, err := inner.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	// Every client is served or, under the limit, evicted; none waits.
	var wg sync.WaitGroup
	for range clients {
		wg.Go(func() {
			c, err := net.Dial("tcp", m.Addr().String())
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = c.Write([]byte("NN"))
			_, _ = c.Read(make([]byte, 1))
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("clients still waiting: %+v", m.Stats())
	}
	waitPending(t, m.Mux, 0)
	if st := m.Stats(); st.Delivered == 0 || st.Timeouts != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestProxyProtocol(t *testing.T) {
	modes := map[string]proxyproto.Policy{"127.0.0.1": proxyproto.Required}
	log := newErrorLog()
	m := startMux(t, log.option(), WithProxyProtocol(func(_ string, remote, _ net.Addr) proxyproto.Policy {
		return modes[remote.(*net.TCPAddr).IP.String()]
	}))
	bridge := m.Listen(Prefix("TST"))
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("PROXY TCP4 192.0.2.1 198.51.100.2 40000 443\r\nTS"))
	time.Sleep(20 * time.Millisecond)
	_, _ = c.Write([]byte("Tdata"))
	got := accept(t, bridge)
	if b := readN(t, got, 7); string(b) != "TSTdata" {
		t.Fatalf("read %q", b)
	}
	if got.RemoteAddr().String() != "192.0.2.1:40000" || got.LocalAddr().String() != "198.51.100.2:443" {
		t.Fatalf("addresses %v %v", got.RemoteAddr(), got.LocalAddr())
	}
	if got.ProxyHeader() == nil || got.ProxyHeader().Version != 1 {
		t.Fatalf("header = %+v", got.ProxyHeader())
	}

	missing := dial(t, m)
	_, _ = missing.Write([]byte("TSTdata"))
	expectClosed(t, missing)
	if err := log.wait(t); !errors.Is(err, proxyproto.ErrNoHeader) {
		t.Fatalf("reported %v, want proxyproto.ErrNoHeader", err)
	}
	for data, want := range map[string]error{
		"PROXY TCP4 bad\r\nTST":     proxyproto.ErrMalformed,
		"PROXY TCP4 192.0.2.1 198.": io.ErrUnexpectedEOF,
	} {
		c := dial(t, m)
		_, _ = c.Write([]byte(data))
		_ = c.(*net.TCPConn).CloseWrite()
		expectClosed(t, c)
		if err := log.wait(t); !errors.Is(err, want) {
			t.Fatalf("%q: reported %v, want %v", data, err, want)
		}
	}
}

func TestProxyProtocolOptionalAndNone(t *testing.T) {
	var mode proxyproto.Policy
	var mu sync.Mutex
	m := startMux(t, WithProxyProtocol(func(_ string, _, _ net.Addr) proxyproto.Policy {
		mu.Lock()
		defer mu.Unlock()
		return mode
	}))
	proxyLine := m.Listen(Prefix("PROXY "))
	bridge := m.Listen(Prefix("TST"))
	silent := m.Listen(Silent(20 * time.Millisecond))
	serve(t, m)
	setMode := func(v proxyproto.Policy) {
		mu.Lock()
		mode = v
		mu.Unlock()
	}

	setMode(proxyproto.Optional)
	c := dial(t, m)
	_, _ = c.Write([]byte("TST"))
	if got := accept(t, bridge); got.ProxyHeader() != nil {
		t.Fatal("header without PROXY bytes")
	}
	v2 := v2Header(t, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}, &net.TCPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 443})
	c = dial(t, m)
	_, _ = c.Write(append(v2, "TST"...))
	if got := accept(t, bridge); got.RemoteAddr().String() != "192.0.2.1:40000" {
		t.Fatalf("RemoteAddr = %v", got.RemoteAddr())
	}
	// A client that waits for the server sends no header either, and goes
	// to the silent route rather than waiting for one until the sniff
	// timeout.
	dial(t, m)
	if got := accept(t, silent); got.ProxyHeader() != nil {
		t.Fatal("header from a silent client")
	}

	setMode(proxyproto.Ignore)
	c = dial(t, m)
	_, _ = c.Write([]byte("PROXY TCP4 192.0.2.1 198.51.100.2 40000 443\r\nTST"))
	got := accept(t, proxyLine)
	if got.ProxyHeader() != nil || got.RemoteAddr().String() == "192.0.2.1:40000" {
		t.Fatal("header parsed for an untrusted peer")
	}
}

func TestMatcherPanicIsContained(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	m.Listen(MatcherFunc(func(in *Input) Result {
		switch {
		case len(in.Bytes()) < 4:
			return NeedMore
		case bytes.HasPrefix(in.Bytes(), []byte("boom")):
			panic("bad matcher")
		}
		return NoMatch
	}))
	rest := m.Listen(AnyBytes())
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("boom"))
	expectClosed(t, c)
	if err := log.wait(t); err == nil || !strings.Contains(err.Error(), "bad matcher") {
		t.Fatalf("reported %v", err)
	}
	c = dial(t, m)
	_, _ = c.Write([]byte("fine"))
	accept(t, rest)
}

func TestConnCopyPaths(t *testing.T) {
	m := startMux(t)
	route := m.Listen(Prefix("TST"))
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("TSTpayload"))
	got := accept(t, route)

	done := make(chan error, 1)
	go func() {
		// Hide WriterTo so that io.Copy goes through Conn.ReadFrom.
		_, err := io.Copy(got, struct{ io.Reader }{strings.NewReader("reply")})
		if err == nil {
			err = got.CloseWrite()
		}
		done <- err
	}()
	reply, err := io.ReadAll(c)
	if err != nil || string(reply) != "reply" {
		t.Fatalf("reply %q, %v", reply, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	_ = c.(*net.TCPConn).CloseWrite()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, got); err != nil || buf.String() != "TSTpayload" {
		t.Fatalf("copied %q, %v", buf.String(), err)
	}
}

func TestConnUnsupportedHalfClose(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	c := &Conn{conn: c1, pending: []byte("ab")}
	if err := c.CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("CloseWrite = %v", err)
	}
	if err := c.CloseRead(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("CloseRead = %v", err)
	}
	b := make([]byte, 1)
	if n, _ := c.Read(b); n != 1 || b[0] != 'a' {
		t.Fatalf("Read = %d %q", n, b)
	}
	_ = c.Close()
	if _, err := c.Read(b); err == nil {
		t.Fatal("Read after Close succeeded")
	}
}

func TestConcurrentConnections(t *testing.T) {
	m := startMux(t)
	routes := map[string]net.Listener{
		"A": m.Listen(Prefix("A")),
		"B": m.Listen(HTTP1(Host("b.example"))),
		"C": m.Listen(AnyBytes()),
	}
	serve(t, m)
	for name, l := range routes {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = c.Close() }()
					_, _ = io.Copy(io.Discard, io.LimitReader(c, 1))
					_, _ = c.Write([]byte(name))
				}()
			}
		}()
	}
	payloads := map[string]string{
		"A": "Ahello",
		"B": "GET / HTTP/1.1\r\nHost: b.example\r\n\r\n",
		"C": "\x01zzz",
	}
	var wg sync.WaitGroup
	errs := make(chan error, 300)
	// Stay below the default listen backlog of macOS.
	inflight := make(chan struct{}, 64)
	for i := range 300 {
		name := "ABC"[i%3 : i%3+1]
		inflight <- struct{}{}
		wg.Go(func() {
			defer func() { <-inflight }()
			c, err := net.Dial("tcp", m.Addr().String())
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write([]byte(payloads[name])); err != nil {
				errs <- err
				return
			}
			b := make([]byte, 1)
			if _, err := io.ReadFull(c, b); err != nil || string(b) != name {
				errs <- fmt.Errorf("route %s: got %q, %v", name, b, err)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestNewPanics(t *testing.T) {
	expectPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		fn()
	}
	m := startMux(t)
	expectPanic("nil listener", func() { _ = m.Serve(nil) })
	expectPanic("nil matcher", func() { m.Listen(AnyBytes(), nil) })
}

// TestMaxSniffBytesAfterProxyHeader checks that matchers see at most the
// sniff limit after a PROXY header, whose read may take more bytes, and that
// the connection still replays all of them.
func TestMaxSniffBytesAfterProxyHeader(t *testing.T) {
	header := v2Header(t, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}, &net.TCPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 443})
	data := append(header, bytes.Repeat([]byte("x"), 1000)...)
	m := New(WithMaxSniffBytes(16), WithProxyProtocol(func(string, net.Addr, net.Addr) proxyproto.Policy { return proxyproto.Required }))
	defer func() { _ = m.Close() }()
	seen := 0
	replayed := 0
	if _, err := m.Add(RouteConfig{Matchers: []Matcher{MatcherFunc(func(in *Input) Result {
		seen = max(seen, len(in.Bytes()))
		if !in.Final() {
			return NeedMore
		}
		return Match
	})}, Handler: func(c *Conn) {
		replayed = len(c.Unread())
		_ = c.Close()
	}}); err != nil {
		t.Fatal(err)
	}
	if err := m.ServeConn(&memConn{data: data}); err != nil {
		t.Fatal(err)
	}
	if seen != 16 || replayed != 1000 {
		t.Fatalf("matchers saw %d bytes, the connection replays %d", seen, replayed)
	}
}
