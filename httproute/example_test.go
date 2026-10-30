package httproute_test

import (
	"context"
	"crypto/tls"
	"log"
	"net"

	"github.com/djylb/netx/httprewrite"
	"github.com/djylb/portmux"
	"github.com/djylb/portmux/httproute"
)

// One port serves plain HTTP and HTTPS through the same routes: portmux
// tells them apart, and the TLS connections are terminated before the
// Router sees them.
func Example() {
	headers, err := httprewrite.ParseRules(`
X-Real-IP: ${remote_addr}
X-Forwarded-For: ${proxy_add_x_forwarded_for}
X-Forwarded-Proto: ${scheme}
`, httproute.Vars())
	if err != nil {
		log.Fatal(err)
	}
	table, err := httproute.Build(httproute.Config{
		Upstreams: []httproute.Upstream{{
			Name: "app",
			Dial: func(ctx context.Context, d httproute.DialInfo) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "tcp", "127.0.0.1:8080")
			},
		}},
		Routes: []httproute.Route{
			{Name: "api", Hosts: []string{"*.example.com"}, Path: "/api", RedirectHTTPS: &httproute.HTTPSRedirect{},
				Proxy: &httproute.Proxy{Upstream: "app", ReplacePath: "/"}, RequestHeaders: headers},
			{Name: "site", Hosts: []string{"example.com"}, Proxy: &httproute.Proxy{Upstream: "app"}, RequestHeaders: headers},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	router := httproute.New(httproute.Options{})
	if err := router.Update(table); err != nil {
		log.Fatal(err)
	}

	config := &tls.Config{NextProtos: []string{"h2", "http/1.1"}} // and certificates
	m := portmux.New()
	_, _ = m.Add(portmux.RouteConfig{Name: "https", Matchers: []portmux.Matcher{portmux.TLS()},
		Handler: func(c *portmux.Conn) { _ = router.ServeConn(tls.Server(c, config)) }})
	_, _ = m.Add(portmux.RouteConfig{Name: "http", Matchers: []portmux.Matcher{portmux.HTTP1()},
		Handler: func(c *portmux.Conn) { _ = router.ServeConn(c) }})
	_ = m // m.Serve(listener)
}
