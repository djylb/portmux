package portmux

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/hostmatch"
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

	// values are the ones of SetValue, in the order set.
	values []inputValue
	// name is the name of SetRequestedName, when named.
	name  hostmatch.Name
	named bool

	// memo keeps the decisions of the first Regexp matchers that decided,
	// which do not change, so that a matcher that waits for more bytes in
	// the same route does not run their expressions again on every read.
	memo  [4]memoEntry
	nmemo int
}

type inputValue struct{ key, value any }

// Value returns the value that SetValue stored under key for this
// connection, or nil.
func (in *Input) Value(key any) any {
	for _, v := range in.values {
		if v.key == key {
			return v.value
		}
	}
	return nil
}

// SetValue stores value under key for the rest of the matching of this
// connection, so that a Matcher of your own can keep the state of an
// incremental parse across calls, as the parsers of Input do, and share it
// with other matchers. key must be comparable; to avoid collisions, use a
// value of an unexported type, as for context keys. SetBytes with shorter
// data drops the values, as it does the parses.
func (in *Input) SetValue(key, value any) {
	for i := range in.values {
		if in.values[i].key == key {
			in.values[i].value = value
			return
		}
	}
	in.values = append(in.values, inputValue{key, value})
}

type memoEntry struct {
	m   *regexpMatcher
	res Result
}

// recalled returns the decision that m made on the input, if it was kept.
func (in *Input) recalled(m *regexpMatcher) (Result, bool) {
	for _, e := range in.memo[:in.nmemo] {
		if e.m == m {
			return e.res, true
		}
	}
	return NoMatch, false
}

// remember keeps the decision of m, while there is room.
func (in *Input) remember(m *regexpMatcher, res Result) {
	if in.nmemo < len(in.memo) {
		in.memo[in.nmemo] = memoEntry{m, res}
		in.nmemo++
	}
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
		in.nmemo = 0
		clear(in.values)
		in.values = in.values[:0]
		in.name, in.named = hostmatch.Name{}, false
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

// SetRequestedName sets the host name that the connection asks for, for a
// protocol of your own that names its target: Domain, ResolveHosts,
// ResolveDomain, Conn.RequestedName and Event.Name then see it, in place of
// the parsed TLS and HTTP names. It is normalized as hostmatch.Normalize
// does; a name that is not a valid host name matches no name. Like a value,
// it lasts for the rest of the matching of the connection.
func (in *Input) SetRequestedName(name string) {
	in.name, in.named = hostmatch.Normalize(name), true
}

// Elapsed returns, during a check for silence, how long the connection has
// been taken without sending anything: the checks run, for connections that
// sent nothing, at the times that the Silencers among the matchers report.
// At other calls it returns zero.
func (in *Input) Elapsed() time.Duration {
	return in.elapsed
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

// RDPCookie returns the cookie of a Remote Desktop connection request, the
// routing token that load balancers route by, for example in a resolver: the
// user name of "Cookie: mstshash=name" or the token of "Cookie: msts=token".
// It returns NoMatch for input that is not a connection request or has no
// cookie, and NeedMore while the request is incomplete.
func (in *Input) RDPCookie() (string, Result) {
	cookie, res := rdpCookie(in.data)
	if res == NeedMore && in.final {
		return "", NoMatch
	}
	return cookie, res
}
