package tlshello_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/djylb/portmux/tlshello"
)

// Read the server name of a TLS connection as its bytes arrive, before
// deciding how to serve it.
func ExampleScanner() {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: "www.example.com", NextProtos: []string{"h2"}}).Handshake()
	}()

	var s tlshello.Scanner
	var data []byte
	buf := make([]byte, 512)
	for {
		n, err := server.Read(buf)
		data = append(data, buf[:n]...)
		hello, perr := s.Scan(data)
		if perr == nil {
			fmt.Println(hello.ServerName, hello.ALPN)
			return
		}
		if err != nil || errors.Is(perr, tlshello.ErrInvalid) {
			fmt.Println(err, perr)
			return
		}
	}
	// Output: www.example.com [h2]
}
