package portmux_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/portmux"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/ipmatch"
	"github.com/djylb/portmux/tlshello"
)

// These tests use the package from outside, through its public API only.

// captureHello returns the ClientHello that crypto/tls sends for name.
func captureHello(t *testing.T, name string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: name, NextProtos: []string{"h2"}, InsecureSkipVerify: true}).Handshake()
		_ = client.Close()
	}()
	// Peek reads exactly the bytes TLS needs to decide, then the hello is in
	// Unread.
	conn, err := portmux.Peek(server, portmux.TLS(), portmux.WithSniffTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return conn.Unread()
}

func TestExternalParsers(t *testing.T) {
	raw := captureHello(t, "a.example.com")
	hello, err := tlshello.Parse(raw)
	if err != nil || hello.ServerName != "a.example.com" || hello.ALPN[0] != "h2" {
		t.Fatalf("tlshello.Parse = %+v, %v", hello, err)
	}
	if _, err := tlshello.Parse(raw[:len(raw)/2]); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("half a hello: %v", err)
	}

	req, err := httphead.Parse([]byte("POST /v1/x HTTP/1.1\r\nHost: api.example.com:8443\r\nContent-Length: 2\r\n\r\nok"))
	if err != nil || req.Method != "POST" || hostmatch.SplitHost(req.Host) != "api.example.com" ||
		req.Header().Get("Content-Length") != "2" {
		t.Fatalf("httphead.Parse = %+v, %v", req, err)
	}
}

func TestExternalPeekAndRestore(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	const msg = "GET /x HTTP/1.1\r\nHost: h.example\r\n\r\nbody"
	go func() { _, _ = client.Write([]byte(msg)) }()

	conn, err := portmux.Peek(server, portmux.HTTP1(portmux.Host("*.example")))
	if err != nil {
		t.Fatal(err)
	}
	if conn.HTTPRequest().Path != "/x" {
		t.Fatalf("request %+v", conn.HTTPRequest())
	}
	// Unread holds what Peek read, at least the head; the stream is replayed
	// whole.
	unread := conn.Unread()
	if !bytes.HasPrefix([]byte(msg), unread) || len(unread) < len(msg)-len("body") {
		t.Fatalf("Unread = %q", unread)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != msg {
		t.Fatalf("read %q, %v", buf, err)
	}
	if conn.Unread() != nil {
		t.Fatal("Unread after the replay")
	}
}

func TestExternalMatchersAndSets(t *testing.T) {
	m := portmux.And(
		portmux.RemoteIP(netip.MustParsePrefix("10.0.0.0/8")),
		portmux.HTTP1(portmux.Host("*.example.com"), portmux.NoneOf(portmux.Host("admin.example.com"))),
	)
	in := portmux.NewInput(&net.TCPAddr{IP: net.ParseIP("10.0.0.7"), Port: 1}, nil)
	in.SetBytes([]byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"), false)
	if got := m.Match(in); got != portmux.Match {
		t.Fatalf("Match = %v", got)
	}
	if got := fmt.Sprint(m); got != `And(RemoteIP(10.0.0.0/8), HTTP1(Host("*.example.com"), NoneOf(Host("admin.example.com"))))` {
		t.Fatalf("description %s", got)
	}
	// Filters also work on their own.
	if !portmux.SNI("*.example.com").Match(&tlshello.Hello{ServerName: "a.example.com"}) {
		t.Fatal("SNI filter")
	}
	hosts := hostmatch.NewSet("*.example.com")
	ips := ipmatch.NewSet(netip.MustParsePrefix("192.0.2.0/24"))
	if !hosts.Match("a.example.com") || !ips.Contains(netip.MustParseAddr("192.0.2.9")) {
		t.Fatal("sets")
	}
}
