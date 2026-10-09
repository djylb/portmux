package portmux

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/tlshello"
)

// Input holds what is known about a connection while it is being matched.
// Parsed protocol heads are cached and parsing resumes where it stopped, so
// every matcher on a connection shares one incremental parse.
type Input struct {
	data    []byte
	final   bool
	elapsed time.Duration
	remote  net.Addr
	local   net.Addr
	peer    net.Addr
	proxy   *proxyproto.Header
	entry   string

	hello *tlshello.Hello
	tls   tlshello.Scanner
	tlsP  parseState
	req   *httphead.Request
	http  httphead.Scanner
	httpP parseState
	req2  *httphead.Request
	h2    httphead.HTTP2Scanner
	h2P   parseState
}

// parseState is the result of a protocol parser on the input so far.
type parseState struct {
	res     Result
	started bool
}

// step runs scan when it may change the result of the last run: at first,
// and while it needs more, once the data reached need or ended.
func (in *Input) step(p *parseState, need int, scan func() error) Result {
	if !p.started || p.res == NeedMore && (len(in.data) >= need || in.final) {
		p.started = true
		switch err := scan(); {
		case err == nil:
			p.res = Match
		case errors.Is(err, io.ErrUnexpectedEOF) && !in.final:
			p.res = NeedMore
		default:
			p.res = NoMatch
		}
	}
	return p.res
}

// NewInput returns an Input for running matchers outside a Mux, for example
// to test a matcher or to match bytes received elsewhere. remote and local
// are the addresses that address matchers see, and may be nil. Call SetBytes
// with the bytes received so far before calling a matcher.
func NewInput(remote, local net.Addr) *Input {
	return &Input{remote: remote, local: local, peer: remote}
}

// SetBytes sets the bytes received so far; final reports that no more will
// arrive. Each call should pass the bytes of the previous one followed by the
// new ones, so that parses continue where they stopped; shorter data starts
// them over. Matchers must not call SetBytes on the Input they are given.
func (in *Input) SetBytes(data []byte, final bool) {
	if len(data) < len(in.data) {
		in.hello, in.tls, in.tlsP = nil, tlshello.Scanner{}, parseState{}
		in.req, in.http, in.httpP = nil, httphead.Scanner{}, parseState{}
		in.req2, in.h2, in.h2P = nil, httphead.HTTP2Scanner{}, parseState{}
	}
	in.data, in.final = data, final
}

// Bytes returns the bytes received so far, after any PROXY protocol header.
// The slice is only valid during the Match call and must not be modified.
func (in *Input) Bytes() []byte {
	return in.data
}

// Final reports whether no more bytes will arrive before the decision: the
// client closed its side, or the sniff size limit was reached. A NeedMore
// result is treated as NoMatch on final input.
func (in *Input) Final() bool {
	return in.final
}

// RemoteAddr returns the client address, taken from the PROXY protocol header
// when one was parsed.
func (in *Input) RemoteAddr() net.Addr {
	return in.remote
}

// LocalAddr returns the address the client connected to, taken from the PROXY
// protocol header when one was parsed.
func (in *Input) LocalAddr() net.Addr {
	return in.local
}

// Entry returns the name of the entry the connection came through; see
// Mux.Entry.
func (in *Input) Entry() string {
	return in.entry
}

// SetEntry sets the entry that Entry reports, for running matchers outside a
// Mux. Matchers must not call it on the Input they are given.
func (in *Input) SetEntry(name string) {
	in.entry = name
}

// PeerAddr returns the address of the TCP peer itself. It differs from
// RemoteAddr when a PROXY protocol header was parsed: the peer is then the
// proxy that sent it.
func (in *Input) PeerAddr() net.Addr {
	return in.peer
}

// ProxyHeader returns the PROXY protocol header, or nil.
func (in *Input) ProxyHeader() *proxyproto.Header {
	return in.proxy
}

// ClientHello parses the input as a TLS ClientHello with tlshello. It
// returns Match and the parsed hello once a complete, well-formed ClientHello
// was received, and NoMatch when the input is not one.
func (in *Input) ClientHello() (*tlshello.Hello, Result) {
	res := in.step(&in.tlsP, in.tls.Need(), func() (err error) {
		in.hello, err = in.tls.Scan(in.data)
		return err
	})
	if res != Match {
		return nil, res
	}
	return in.hello, Match
}

// HTTPRequest parses the input as the head of an HTTP/1.x request with
// httphead. It returns Match and the parsed request once the request line and
// every header field were received, and NoMatch when the input is not an
// HTTP/1.x request.
func (in *Input) HTTPRequest() (*httphead.Request, Result) {
	res := in.step(&in.httpP, in.http.Need(), func() (err error) {
		in.req, err = in.http.Scan(in.data)
		return err
	})
	if res != Match {
		return nil, res
	}
	return in.req, Match
}

// HTTP2Request parses the input as a cleartext HTTP/2 connection with prior
// knowledge, with httphead. It returns Match and the first request once its
// header block was received, and NoMatch when the input is not such a
// connection; see HTTP2.
func (in *Input) HTTP2Request() (*httphead.Request, Result) {
	res := in.step(&in.h2P, in.h2.Need(), func() (err error) {
		in.req2, err = in.h2.Scan(in.data)
		return err
	})
	if res != Match {
		return nil, res
	}
	return in.req2, Match
}
