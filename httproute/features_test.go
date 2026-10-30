package httproute

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/forwarded"
	"github.com/djylb/netx/proxyproto"
)

func TestErrorPageVariables(t *testing.T) {
	checkLeaks(t)
	_, base := startRouter(t, Options{}, Config{
		ErrorPages: map[int]ErrorPage{404: {Body: []byte("<p>${status} ${request_uri} $$ ${request_id}</p>\n")}},
		Routes:     []Route{{Path: "/only", Respond: okRespond}},
	})
	_, r := rawRequest(t, base, "GET /nope?q=<b> HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	res, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !regexp.MustCompile(`^<p>404 /nope\?q=&lt;b&gt; \$ [0-9a-f]{16}</p>\n$`).Match(body) {
		t.Errorf("page %q", body)
	}
	if _, err := Build(Config{ErrorPages: map[int]ErrorPage{500: {Body: []byte("${nope}")}}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("unknown variable: %v", err)
	}
}

func TestPathRegexpTemplate(t *testing.T) {
	checkLeaks(t)
	_, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{backend(t, "b", echo)},
		Routes: []Route{{PathRegexp: `^/u/(\d+)$`, Proxy: &Proxy{Upstream: "b", PathTemplate: template(t, "/users/${match_1}")},
			RequestHeaders: rules(t, "X-Id: ${match_1}")}},
	})
	res, _ := get(t, client(t), "GET", base+"/u/42?x=1", "a", nil)
	if res.Header.Get("Got-URI") != "/users/42?x=1" || res.Header.Get("Got-X-Id") != "42" {
		t.Errorf("%v", res.Header)
	}
	if _, err := Build(Config{Routes: []Route{{PathRegexp: strings.Repeat("a", MaxRegexpLen+1), Respond: okRespond}}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("long regexp: %v", err)
	}
}

func TestUpgradeIdleTimeout(t *testing.T) {
	checkLeaks(t)
	_, base := startRouter(t, Options{}, Config{Upstreams: []Upstream{wsBackend(t)},
		Routes: []Route{{Proxy: &Proxy{Upstream: "ws"}, UpgradeIdleTimeout: 100 * time.Millisecond}}})
	conn, br := rawRequest(t, base, "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	if res, err := http.ReadResponse(br, nil); err != nil || res.StatusCode != 101 {
		t.Fatalf("%v %v", res, err)
	}
	for range 3 { // traffic keeps it open past the timeout
		time.Sleep(60 * time.Millisecond)
		_, _ = io.WriteString(conn, "x\n")
		if line, err := br.ReadString('\n'); line != "x\n" {
			t.Fatalf("%q %v", line, err)
		}
	}
	start := time.Now()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("read after idle timeout")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("closed after %v", d)
	}
}

func TestBasicAuth(t *testing.T) {
	checkLeaks(t)
	hash, err := HashPassword("s3cret", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPassword(hash, "s3cret"); !ok || err != nil {
		t.Errorf("verify: %v %v", ok, err)
	}
	if ok, _ := VerifyPassword(hash, "wrong"); ok {
		t.Error("wrong password verified")
	}
	if _, err := VerifyPassword("$pbkdf2-sha256$i=x$a$b", "p"); !errors.Is(err, ErrHash) {
		t.Errorf("bad hash: %v", err)
	}
	for _, a := range []*BasicAuth{{}, {Users: map[string]string{"u": "plain"}}, {Users: map[string]string{"a:b": hash}}, {Realm: "a\nb", Users: map[string]string{"u": hash}}} {
		if _, err := Build(Config{Routes: []Route{{Respond: okRespond, BasicAuth: a}}}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v: %v", a, err)
		}
	}
	_, base := startRouter(t, Options{}, Config{Routes: []Route{
		{Path: "/users", Respond: okRespond, BasicAuth: &BasicAuth{Realm: `my "zone"`, Users: map[string]string{"alice": hash}}},
		{Path: "/func", Respond: okRespond, BasicAuth: &BasicAuth{Verify: func(_ *http.Request, u, p string) bool { return u == "bob" && p == "pw" }}},
	}})
	c := client(t)
	auth := func(path, user, pass string) *http.Response {
		req, _ := http.NewRequest("GET", base+path, nil)
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(res.Body)
		_ = res.Body.Close()
		return res
	}
	res := auth("/users", "", "")
	if res.StatusCode != 401 || res.Header.Get("Www-Authenticate") != `Basic realm="my \"zone\"", charset="UTF-8"` {
		t.Errorf("challenge %d %q", res.StatusCode, res.Header.Get("Www-Authenticate"))
	}
	for _, tc := range []struct {
		path, user, pass string
		status           int
	}{
		{"/users", "alice", "wrong", 401},
		{"/users", "mallory", "s3cret", 401},
		{"/users", "alice", "s3cret", 200},
		{"/users", "alice", "s3cret", 200}, // remembered
		{"/func", "bob", "pw", 200},
		{"/func", "bob", "x", 401},
	} {
		if res := auth(tc.path, tc.user, tc.pass); res.StatusCode != tc.status {
			t.Errorf("%s %s:%s: %d, want %d", tc.path, tc.user, tc.pass, res.StatusCode, tc.status)
		}
	}
}

// tlsBackend starts an HTTPS server for h that records the server names
// that clients send, with HTTP/2 when h2 is set.
func tlsBackend(t *testing.T, h2 bool, h http.Handler) (*httptest.Server, *x509.CertPool, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var names []string
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = h2
	srv.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		names = append(names, hello.ServerName)
		mu.Unlock()
		return nil, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv, roots, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), names...)
	}
}

func TestUpstreamServerName(t *testing.T) {
	checkLeaks(t)
	srv, roots, names := tlsBackend(t, false, echo)
	addr := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	toAddr := func(ctx context.Context, _ DialInfo) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	_, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{
			// An IP address: the outgoing Host is the name.
			{Name: "ip", Addr: addr, TLS: &tls.Config{RootCAs: roots}},
			{Name: "explicit", Addr: addr, ServerName: "example.com", TLS: &tls.Config{RootCAs: roots}},
			// A name: the name of Addr.
			{Name: "named", Addr: "localhost:" + port, Dial: toAddr, TLS: &tls.Config{InsecureSkipVerify: true}},
		},
		Routes: []Route{
			{Path: "/ip", Proxy: &Proxy{Upstream: "ip"}},
			{Path: "/explicit", Proxy: &Proxy{Upstream: "explicit"}},
			{Path: "/named", Proxy: &Proxy{Upstream: "named"}},
		},
	})
	c := client(t)
	for _, tc := range []struct{ path, host, sni string }{
		{"/ip", "example.com", "example.com"},
		{"/explicit", "other.org", "example.com"},
		{"/named", "other.org", "localhost"},
	} {
		before := len(names())
		res, _ := get(t, c, "GET", base+tc.path, tc.host, nil)
		if res.StatusCode != 200 || res.Header.Get("Got-Host") != tc.host {
			t.Errorf("%s: %d %v", tc.path, res.StatusCode, res.Header)
			continue
		}
		if n := names(); len(n) != before+1 || n[before] != tc.sni {
			t.Errorf("%s: server names %q, want %q", tc.path, n[before:], tc.sni)
		}
	}
}

// protoEcho answers with the protocol of the request.
var protoEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Got-Proto", r.Proto)
	w.Header().Set("Got-Remote", r.RemoteAddr)
})

func TestHTTP2Upstream(t *testing.T) {
	checkLeaks(t)
	tlsSrv, roots, _ := tlsBackend(t, true, protoEcho)
	h2c := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			wsBackendHandler(w, r)
			return
		}
		protoEcho(w, r)
	}))
	h2c.Config.Protocols = new(http.Protocols)
	h2c.Config.Protocols.SetHTTP1(true)
	h2c.Config.Protocols.SetUnencryptedHTTP2(true)
	h2c.Start()
	t.Cleanup(h2c.Close)
	_, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{
			{Name: "tls", Addr: tlsSrv.Listener.Addr().String(), HTTP2: true, ServerName: "example.com", TLS: &tls.Config{RootCAs: roots}},
			{Name: "h2c", Addr: h2c.Listener.Addr().String(), HTTP2: true},
		},
		Routes: []Route{{Path: "/tls", Proxy: &Proxy{Upstream: "tls"}}, {Path: "/h2c", Proxy: &Proxy{Upstream: "h2c"}}},
	})
	c := client(t)
	for _, p := range []string{"/tls", "/h2c"} {
		res, _ := get(t, c, "GET", base+p, "x", nil)
		if res.StatusCode != 200 || res.Header.Get("Got-Proto") != "HTTP/2.0" {
			t.Errorf("%s: %d %q", p, res.StatusCode, res.Header.Get("Got-Proto"))
		}
	}
	// Upgrades go over HTTP/1.1.
	conn, br := rawRequest(t, base, "GET /h2c HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	if res, err := http.ReadResponse(br, nil); err != nil || res.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", res, err)
	}
	_, _ = io.WriteString(conn, "hi\n")
	if line, _ := br.ReadString('\n'); line != "hi\n" {
		t.Errorf("echo %q", line)
	}
	_ = conn.Close()
}

func TestProxyProtocolUpstream(t *testing.T) {
	checkLeaks(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{Listener: &proxyproto.Listener{Listener: ln}, Config: &http.Server{Handler: protoEcho}}
	srv.Start()
	t.Cleanup(srv.Close)
	trusted, _ := forwarded.ParsePrefixSet("127.0.0.0/8")
	_, base := startRouter(t, Options{}, Config{
		Resolver: &forwarded.Resolver{Trusted: trusted},
		Upstreams: []Upstream{
			{Name: "v1", Addr: ln.Addr().String(), ProxyProtocol: 1},
			{Name: "v2", Addr: ln.Addr().String(), ProxyProtocol: 2},
		},
		Routes: []Route{{Path: "/v1", Proxy: &Proxy{Upstream: "v1"}}, {Path: "/v2", Proxy: &Proxy{Upstream: "v2"}}},
	})
	c := client(t)
	for _, p := range []string{"/v1", "/v2"} {
		res, _ := get(t, c, "GET", base+p, "x", http.Header{"X-Forwarded-For": {"203.0.113.9"}})
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Got-Remote"), "203.0.113.9:") {
			t.Errorf("%s: %d remote %q", p, res.StatusCode, res.Header.Get("Got-Remote"))
		}
	}
	if _, err := Build(Config{Upstreams: []Upstream{{Name: "x", Addr: "a:1", ProxyProtocol: 2, HTTP2: true}}}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("PROXY with HTTP2: %v", err)
	}
}
