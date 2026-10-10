package portmux

import (
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/djylb/portmux/internal/testutil"
)

var benchRequest = []byte("GET /api/v1/items?page=2 HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: bench\r\n" +
	"Accept: */*\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n")

// memConn returns its data once and accepts deadlines.
type memConn struct {
	data []byte
	off  int
}

func (c *memConn) Read(p []byte) (int, error) {
	n := copy(p, c.data[c.off:])
	c.off += n
	return n, nil
}
func (c *memConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *memConn) Close() error                { return nil }
func (c *memConn) LocalAddr() net.Addr         { return memLocal }
func (c *memConn) RemoteAddr() net.Addr        { return memRemote }

var (
	memLocal  = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	memRemote = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}
)

func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

// benchServeConn measures matching and delivering one connection against a
// typical route table, without network I/O.
func benchServeConn(b *testing.B, data []byte) {
	m := New()
	defer func() { _ = m.Close() }()
	m.Match(Prefix("TST"))
	m.Match(HTTP1(Host("manager.example.com")))
	m.Match(TLS(SNI("manager.example.com")))
	r := m.Match(HTTP1(), TLS())
	go func() {
		for {
			c, err := r.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	b.ReportAllocs()
	for b.Loop() {
		if err := m.ServeConn(&memConn{data: data}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServeConnTLS(b *testing.B) {
	benchServeConn(b, testutil.ClientHelloBytes(b, &tls.Config{ServerName: "www.example.com", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}))
}

func BenchmarkServeConnHTTP(b *testing.B) {
	benchServeConn(b, benchRequest)
}

// BenchmarkServeConnParallel measures matching from many goroutines at once,
// with one accept loop per route as servers run them.
func BenchmarkServeConnParallel(b *testing.B) {
	benchParallel(b, 1)
}

// BenchmarkServeConnParallelAcceptors adds an accept loop per CPU on one
// route, which makes the route's channel the point of contention.
func BenchmarkServeConnParallelAcceptors(b *testing.B) {
	benchParallel(b, runtime.GOMAXPROCS(0))
}

func benchParallel(b *testing.B, acceptors int) {
	hello := testutil.ClientHelloBytes(b, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
	m := New()
	defer func() { _ = m.Close() }()
	m.Match(Prefix("TST"))
	m.Match(HTTP1(Host("manager.example.com")))
	r := m.Match(HTTP1(), TLS())
	for range acceptors {
		go func() {
			for {
				c, err := r.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			data := hello
			if rand.IntN(2) == 0 {
				data = benchRequest
			}
			if err := m.ServeConn(&memConn{data: data}); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkLoopback measures whole connections over loopback TCP: dial, send
// a ClientHello, route and close.
func BenchmarkLoopback(b *testing.B) {
	hello := testutil.ClientHelloBytes(b, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	m := New()
	defer func() { _ = m.Close() }()
	r := m.Match(TLS())
	go func() { _ = m.Serve(ln) }()
	go func() {
		for {
			c, err := r.AcceptConn()
			if err != nil {
				return
			}
			closeNow(c)
		}
	}()
	runClients(b, ln.Addr().String(), hello)
}

// runClients runs b's loop in parallel clients that each dial addr, send
// hello and wait until the server closes the connection.
func runClients(b *testing.B, addr string, hello []byte) {
	b.ReportAllocs()
	b.SetParallelism(4)
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 1)
		for pb.Next() {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				b.Error(err)
				return
			}
			_, _ = c.Write(hello)
			_, _ = c.Read(buf) // returns when the server closes
			_ = c.Close()
		}
	})
}

// BenchmarkHostRoutes matches a request for the last of n routes that each
// filter one host, a path and a header.
func BenchmarkHostRoutes(b *testing.B) {
	for _, n := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := routeSet{routes: make(map[*Route]routeState)}
			for i := range n {
				s.routes[&Route{seq: uint64(i)}] = routeState{matchers: []Matcher{
					HTTP1(Host(fmt.Sprintf("h%d.Example.com", i)), NoneOf(PathPrefix("/internal/")), Header("X-Kind")),
				}}
			}
			t := newTable(s)
			data := []byte(fmt.Sprintf("GET /api HTTP/1.1\r\nHost: H%d.example.com:443\r\nUser-Agent: x\r\nX-Kind: a\r\n\r\n", n-1))
			dead := make([]bool, n)
			b.ReportAllocs()
			for b.Loop() {
				in := &Input{data: data}
				clear(dead)
				if _, _, res := t.other.evaluate(dead, in); res != Match {
					b.Fatal(res)
				}
			}
		})
	}
}

// BenchmarkServeConnAlways measures a dedicated entry, where a route with
// Always hands each connection over without reading from it.
func BenchmarkServeConnAlways(b *testing.B) {
	m := New()
	defer func() { _ = m.Close() }()
	// Rules of other entries are not asked; a global rule that waits for
	// bytes would be, so the dedicated route comes first.
	m.Match(HTTP1(Host("other.example.com")))
	if _, err := m.Add(RouteConfig{Entries: []string{"web"}, Matchers: []Matcher{HTTP1()}}); err != nil {
		b.Fatal(err)
	}
	r, err := m.Add(RouteConfig{Priority: 100, Entries: []string{"tcp"}, Matchers: []Matcher{Always()}})
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		for {
			c, err := r.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	entry := m.Entry("tcp")
	b.ReportAllocs()
	for b.Loop() {
		if err := entry.ServeConn(&memConn{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkChangeRoutes measures one route change in a Mux laid out as a
// tunnel server: a dedicated entry per tunnel port, many sites on the web
// entries and a few rules for every entry.
func BenchmarkChangeRoutes(b *testing.B) {
	for _, tunnels := range []int{100, 1000} {
		b.Run(fmt.Sprint(tunnels), func(b *testing.B) {
			m := New()
			defer func() { _ = m.Close() }()
			err := m.Batch(func(batch *Batch) error {
				for i := range 3 {
					if _, err := batch.Add(RouteConfig{Priority: 100, Reject: true, Matchers: []Matcher{LocalPort(uint16(i + 1))}}); err != nil {
						return err
					}
				}
				for i := range 500 {
					cfg := RouteConfig{Entries: []string{"http", "https"}, Matchers: []Matcher{Domain(fmt.Sprintf("h%d.example.com", i))}}
					if _, err := batch.Add(cfg); err != nil {
						return err
					}
				}
				for i := range tunnels {
					cfg := RouteConfig{Entries: []string{fmt.Sprintf("tcp-%d", i)}, Matchers: []Matcher{Always()}}
					if _, err := batch.Add(cfg); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				b.Fatal(err)
			}
			r := m.Routes()[10]
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				if err := r.SetPriority(i % 2); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDelivery compares handing connections to an accept loop with
// passing them to a handler, over loopback TCP with a server goroutine per
// connection as servers run them.
func BenchmarkDelivery(b *testing.B) {
	hello := testutil.ClientHelloBytes(b, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
	for _, mode := range []string{"accept", "handler"} {
		b.Run(mode, func(b *testing.B) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			m := New()
			defer func() { _ = m.Close() }()
			serveConn := closeNow
			cfg := RouteConfig{Matchers: []Matcher{TLS()}}
			if mode == "handler" {
				cfg.Handler = serveConn
			}
			r, err := m.Add(cfg)
			if err != nil {
				b.Fatal(err)
			}
			if mode == "accept" {
				go func() {
					for {
						c, err := r.AcceptConn()
						if err != nil {
							return
						}
						go serveConn(c)
					}
				}()
			}
			go func() { _ = m.Serve(ln) }()
			runClients(b, ln.Addr().String(), hello)
		})
	}
}

// BenchmarkServeConnHandler is BenchmarkServeConnAlways with a handler
// instead of an accept loop.
func BenchmarkServeConnHandler(b *testing.B) {
	m := New()
	defer func() { _ = m.Close() }()
	if _, err := m.Add(RouteConfig{Matchers: []Matcher{Always()}, Handler: func(c *Conn) { _ = c.Close() }}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := m.ServeConn(&memConn{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkServeConnParallelHandler is BenchmarkServeConnParallel with a
// handler instead of an accept loop.
func BenchmarkServeConnParallelHandler(b *testing.B) {
	hello := testutil.ClientHelloBytes(b, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
	m := New()
	defer func() { _ = m.Close() }()
	m.Match(Prefix("TST"))
	m.Match(HTTP1(Host("manager.example.com")))
	if _, err := m.Add(RouteConfig{Matchers: []Matcher{HTTP1(), TLS()}, Handler: func(c *Conn) { _ = c.Close() }}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			data := hello
			if rand.IntN(2) == 0 {
				data = benchRequest
			}
			if err := m.ServeConn(&memConn{data: data}); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// closeNow closes a connection with a reset, which leaves no TIME_WAIT
// behind, so that benchmarks of many connections do not run out of ports.
func closeNow(c *Conn) {
	if tc, ok := c.NetConn().(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}
