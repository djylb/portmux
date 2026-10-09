package httphead_test

import (
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
)

// Parse bytes that were received elsewhere.
func ExampleParse() {
	req, err := httphead.Parse([]byte("GET /status HTTP/1.1\r\nHost: api.example.com:8080\r\nUser-Agent: probe\r\n\r\n"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(req.Method, hostmatch.SplitHost(req.Host), req.Path, req.Header().Get("User-Agent"))

	_, err = httphead.Parse([]byte("GET /status HTTP/1.1\r\nHost: api"))
	fmt.Println(errors.Is(err, io.ErrUnexpectedEOF))
	// Output:
	// GET api.example.com /status probe
	// true
}
