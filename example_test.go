package portmux_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux"
	"github.com/djylb/portmux/hostmatch"
)

// Serve a custom protocol, an admin site and a public site over TLS, an HTTP
// redirect and SSH clients that wait for the server, on one port.
func Example() {
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	m := portmux.New()

	agents := m.Match(portmux.Prefix("AGENT/1\n"))
	admin := m.Match(portmux.TLS(portmux.SNI("admin.example.com")))
	site := m.Match(portmux.TLS())
	redirect := m.Match(portmux.HTTP1())
	ssh := m.Match(portmux.SSH(), portmux.Silent(2*time.Second))

	go serveAgents(agents)
	go serveAgents(ssh)
	go func() { _ = http.Serve(tls.NewListener(admin, &tls.Config{ /* certificates */ }), adminHandler()) }()
	go func() { _ = http.Serve(tls.NewListener(site, &tls.Config{ /* certificates */ }), publicHandler()) }()
	go func() {
		_ = http.Serve(redirect, http.RedirectHandler("https://example.com/", http.StatusMovedPermanently))
	}()
	log.Fatal(m.Serve(ln))
}

func serveAgents(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(c, c)
		}()
	}
}

func adminHandler() http.Handler  { return http.NotFoundHandler() }
func publicHandler() http.Handler { return http.NotFoundHandler() }

// Route by HTTP host and path, including a WebSocket endpoint.
func ExampleHTTP1() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	m := portmux.New()
	defer func() { _ = m.Close() }()

	_ = m.Match(portmux.HTTP1(portmux.Host("tunnel.example.com"), portmux.Path("/ws"), portmux.WebSocket()))
	api := m.Match(portmux.HTTP1(portmux.Host("*.example.com"), portmux.PathPrefix("/api/")))
	_ = m.Match(portmux.HTTP1())
	go func() { _ = m.Serve(ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = fmt.Fprint(c, "GET /api/users HTTP/1.1\r\nHost: eu.example.com\r\n\r\n")

	conn, err := api.AcceptConn()
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	req := conn.HTTPRequest()
	fmt.Println(req.Method, req.Host, req.Path)
	// Output: GET eu.example.com /api/users
}

// Accept PROXY protocol headers from a trusted load balancer only, and serve
// the admin site to the office network only.
func ExampleWithProxyProtocol() {
	lb := netip.MustParsePrefix("10.0.0.0/24")
	office := netip.MustParsePrefix("203.0.113.0/24")
	m := portmux.New(portmux.WithProxyProtocol(func(_ string, peer, _ net.Addr) proxyproto.Policy {
		if tcp, ok := peer.(*net.TCPAddr); ok && lb.Contains(tcp.AddrPort().Addr().Unmap()) {
			return proxyproto.Required
		}
		return proxyproto.Ignore
	}))
	// RemoteIP sees the client address from the PROXY header.
	_ = m.Match(portmux.And(portmux.RemoteIP(office), portmux.TLS(portmux.SNI("admin.example.com"))))
	_ = m.Match(portmux.TLS())

	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(m.Serve(ln))
}

// A custom matcher can use the parsed protocol heads.
func ExampleMatcherFunc() {
	acme := portmux.MatcherFunc(func(in *portmux.Input) portmux.Result {
		hello, res := in.ClientHello()
		if res != portmux.Match {
			return res
		}
		if slices.Contains(hello.ALPN, "acme-tls/1") {
			return portmux.Match
		}
		return portmux.NoMatch
	})
	fmt.Println(acme.Match(new(portmux.Input)))
	// Output: NeedMore
}

// Change routes at runtime, for example on a configuration reload.
func ExampleMux_Batch() {
	m := portmux.New()
	defer func() { _ = m.Close() }()

	// A fallback with a low priority, then named routes for the admin site.
	_, _ = m.Add(portmux.RouteConfig{Name: "fallback", Priority: -100, Matchers: []portmux.Matcher{portmux.Any()}})
	_, _ = m.Add(portmux.RouteConfig{Name: "admin-http", Matchers: []portmux.Matcher{portmux.HTTP1(portmux.Host("admin.example.com"))}})
	_, _ = m.Add(portmux.RouteConfig{Name: "admin-tls", Matchers: []portmux.Matcher{portmux.TLS(portmux.SNI("admin.example.com"))}})

	// The admin host changed: update both routes in one step. Their listeners,
	// and the servers on them, keep running.
	host := "console.example.com"
	err := m.Batch(func(b *portmux.Batch) error {
		if err := b.SetMatchers(b.Route("admin-http"), portmux.HTTP1(portmux.Host(host))); err != nil {
			return err
		}
		return b.SetMatchers(b.Route("admin-tls"), portmux.TLS(portmux.SNI(host)))
	})
	if err != nil {
		log.Fatal(err)
	}

	// The admin site was turned off.
	_ = m.Route("admin-tls").Close()

	for _, r := range m.Routes() {
		fmt.Println(r.Name(), r.Priority())
	}
	// Output:
	// admin-http 0
	// fallback -100
}

// Terminate TLS on one route and match the protocol inside it with a second
// Mux.
func ExampleMux_Serve_nested() {
	outer := portmux.New()
	secure := outer.Match(portmux.TLS(portmux.SNI("tunnel.example.com")))

	inner := portmux.New()
	agents := inner.Match(portmux.Prefix("AGENT/1\n"))
	web := inner.Match(portmux.HTTP1())
	go func() { _ = inner.Serve(tls.NewListener(secure, &tls.Config{ /* certificates */ })) }()
	go serveAgents(agents)
	go func() { _ = http.Serve(web, publicHandler()) }()

	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(outer.Serve(ln))
}

// Stop taking connections but deliver those already being matched.
func ExampleMux_Shutdown() {
	m := portmux.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		log.Print(err)
	}
	fmt.Println(m.Stats().Pending)
	// Output: 0
}

// Read the SNI of a connection without a Mux, then serve it with the TLS
// configuration for that name.
func ExamplePeek() {
	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	configs := map[string]*tls.Config{ /* one per name */ }
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			conn, err := portmux.Peek(c, portmux.TLS(), portmux.WithSniffTimeout(5*time.Second))
			if err != nil {
				_ = conn.Close()
				return
			}
			config, ok := configs[conn.ClientHello().ServerName]
			if !ok {
				_ = conn.Close()
				return
			}
			// The handshake reads the ClientHello again from conn.
			tc := tls.Server(conn, config)
			defer func() { _ = tc.Close() }()
			_, _ = io.Copy(tc, tc)
		}()
	}
}

// Test a custom matcher with bytes and addresses of your choice.
func ExampleNewInput() {
	office := netip.MustParsePrefix("10.0.0.0/8")
	m := portmux.And(portmux.RemoteIP(office), portmux.Prefix("AGENT/1\n"))

	in := portmux.NewInput(&net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 5000}, nil)
	in.SetBytes([]byte("AGE"), false)
	fmt.Println(m.Match(in))
	in.SetBytes([]byte("AGENT/1\nhello"), false)
	fmt.Println(m.Match(in))
	// Output:
	// NeedMore
	// Match
}

// Serve a route with a handler instead of an accept loop, and a dedicated
// entry whose connections go to it unread.
func ExampleRouteConfig_handler() {
	m := portmux.New()
	_, err := m.Add(portmux.RouteConfig{
		Entries:  []string{"echo"},
		Matchers: []portmux.Matcher{portmux.Always()},
		Handler: func(c *portmux.Conn) {
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(c, c)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":7")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(m.Entry("echo").Serve(ln))
}

// Read a rule kept as text, with a matcher of the program named in it.
func ExampleParseMatcher() {
	names := &portmux.Names{Matchers: map[string]portmux.Matcher{
		"office": portmux.RemoteIP(netip.MustParsePrefix("10.0.0.0/8")),
	}}
	m, err := portmux.ParseMatcher(`And(office, TLS(SNI("admin.example.com"), MinTLSVersion(1.2)))`, names)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(m)
	_, err = portmux.ParseMatcher(`TLS(SNI(admin))`, nil)
	fmt.Println(err)
	// Output:
	// And(office, TLS(SNI("admin.example.com"), MinTLSVersion(1.2)))
	// portmux: matcher "TLS(SNI(admin))": expected a string at offset 8
}

// Keep an HTTPS and an HTTP target per name, and fall back to a wider pattern
// when a name has no target for the protocol.
func ExampleResolveHosts() {
	m := portmux.New()
	defer func() { _ = m.Close() }()
	target := func(name string) *portmux.Route {
		r, err := m.Add(portmux.RouteConfig{Name: name})
		if err != nil {
			log.Fatal(err)
		}
		return r
	}
	type site struct{ https, http *portmux.Route }
	var sites hostmatch.Map[site]
	sites.Set("*.example.com", site{https: target("passthrough"), http: target("web")})
	sites.Set("shop.example.com", site{https: target("shop")}) // HTTPS only
	resolve := portmux.ResolveHosts(&sites, func(in *portmux.Input, _ string, s site) (*portmux.Route, bool) {
		if _, res := in.ClientHello(); res == portmux.Match {
			return s.https, s.https != nil
		}
		return s.http, s.http != nil
	})
	if _, err := m.Add(portmux.RouteConfig{Name: "sites", Resolve: resolve}); err != nil {
		log.Fatal(err)
	}

	in := portmux.NewInput(nil, nil)
	in.SetBytes([]byte("GET / HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"), false)
	r, res := resolve(in)
	fmt.Println(r.Name(), res)
	// Output: web Match
}
