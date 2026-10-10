package portmux

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/internal/testutil"
)

// pair returns both ends of a loopback TCP connection.
func pair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func TestPeekTLS(t *testing.T) {
	client, server := pair(t)
	go func() {
		tc := tls.Client(client, &tls.Config{ServerName: "a.example.com", NextProtos: []string{"h2"}, InsecureSkipVerify: true})
		if err := tc.Handshake(); err == nil {
			_, _ = tc.Write([]byte("ping"))
		}
	}()
	conn, err := Peek(server, TLS(SNI("*.example.com")))
	if err != nil {
		t.Fatal(err)
	}
	if h := conn.ClientHello(); h == nil || h.ServerName != "a.example.com" || h.ALPN[0] != "h2" {
		t.Fatalf("hello %+v", h)
	}
	if conn.Route() != nil || conn.NetConn() != server {
		t.Fatal("Peek returned a routed connection")
	}
	// The handshake runs on the replayed bytes.
	tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate(t)}, NextProtos: []string{"h2"}})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if b := readN(t, tc, 4); string(b) != "ping" {
		t.Fatalf("read %q", b)
	}
}

func TestPeekNoMatchKeepsStream(t *testing.T) {
	client, server := pair(t)
	hello := testutil.ClientHelloBytes(t, &tls.Config{ServerName: "a.example.com", InsecureSkipVerify: true})
	_, _ = client.Write(hello)
	conn, err := Peek(server, HTTP1())
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("Peek = %v", err)
	}
	if b := readN(t, conn, len(hello)); !bytes.Equal(b, hello) {
		t.Fatal("bytes after a failed Peek differ")
	}
	// A filter that rejects still leaves the parse on the connection.
	client2, server2 := pair(t)
	_, _ = client2.Write(hello)
	conn2, err := Peek(server2, TLS(SNI("b.example.com")))
	if !errors.Is(err, ErrNoMatch) || conn2.ClientHello() == nil || conn2.ClientHello().ServerName != "a.example.com" {
		t.Fatalf("Peek = %v, hello %+v", err, conn2.ClientHello())
	}
}

func TestPeekTimeoutAndEOF(t *testing.T) {
	client, server := pair(t)
	conn, err := Peek(server, TLS(), WithSniffTimeout(50*time.Millisecond))
	if !errors.Is(err, ErrSniffTimeout) {
		t.Fatalf("Peek = %v", err)
	}
	// The deadline is cleared: later bytes are read normally.
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = client.Write([]byte("late"))
	}()
	if b := readN(t, conn, 4); string(b) != "late" {
		t.Fatalf("read %q", b)
	}

	client2, server2 := pair(t)
	_, _ = client2.Write([]byte("GE"))
	_ = client2.Close()
	conn2, err := Peek(server2, Prefix("GET"))
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("Peek on a short stream = %v", err)
	}
	if b, _ := io.ReadAll(conn2); string(b) != "GE" {
		t.Fatalf("read %q", b)
	}
	client3, server3 := pair(t)
	_ = client3.Close()
	if _, err := Peek(server3, Any()); !errors.Is(err, io.EOF) {
		t.Fatalf("Peek on a closed stream = %v", err)
	}
}

func TestPeekProxyHeaderAndSilence(t *testing.T) {
	client, server := pair(t)
	_, _ = client.Write([]byte("PROXY TCP4 192.0.2.1 198.51.100.2 40000 443\r\nTSTx"))
	conn, err := Peek(server, And(RemoteIP(netip.MustParsePrefix("192.0.2.0/24")), Prefix("TST")),
		WithProxyProtocol(func(_ string, _, _ net.Addr) proxyproto.Policy { return proxyproto.Required }))
	if err != nil {
		t.Fatal(err)
	}
	if conn.RemoteAddr().String() != "192.0.2.1:40000" || conn.ProxyHeader() == nil {
		t.Fatalf("remote %v", conn.RemoteAddr())
	}
	if b := readN(t, conn, 4); string(b) != "TSTx" {
		t.Fatalf("read %q", b)
	}

	_, silent := pair(t)
	start := time.Now()
	if _, err := Peek(silent, Silent(30*time.Millisecond)); err != nil {
		t.Fatalf("Peek on a silent client = %v", err)
	}
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Fatalf("decided after %v", elapsed)
	}
}

func TestNewInputParsesIncrementally(t *testing.T) {
	remote := &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 5000}
	in := NewInput(remote, nil)
	head := []byte("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
	m := And(RemoteIP(netip.MustParsePrefix("10.0.0.0/8")), HTTP1(Host("example.com")))
	for n := range len(head) {
		in.SetBytes(head[:n], false)
		if got := m.Match(in); got != NeedMore {
			t.Fatalf("after %d bytes: %v", n, got)
		}
	}
	in.SetBytes(head, false)
	if got := m.Match(in); got != Match {
		t.Fatalf("complete head: %v", got)
	}
	req, res := in.HTTPRequest()
	if res != Match || req == nil || req.Path != "/a" || in.RemoteAddr() != remote {
		t.Fatalf("request %+v %v", req, res)
	}
	// Shorter bytes start the parses over.
	in.SetBytes([]byte("\x16\x03"), false)
	if _, res := in.HTTPRequest(); res != NoMatch {
		t.Fatalf("after reset: %v", res)
	}
	in.SetBytes([]byte("GET / HTTP/1.1\r\n"), true)
	if got := HTTP1().Match(in); got != NoMatch {
		t.Fatalf("final partial head: %v", got)
	}
}
