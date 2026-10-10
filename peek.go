package portmux

import (
	"net"
	"sync/atomic"
	"time"
)

// Peek reads the first bytes of c until m matches or rules the connection
// out, without consuming them, as a Mux does for its routes. It needs no Mux,
// so a server that already holds a connection can, for example, read its SNI
// before deciding how to serve it.
//
// Peek returns c wrapped in a Conn that replays the bytes read and carries
// what was parsed: the ClientHello, the HTTP request head and the PROXY
// header. The Conn is returned whatever the outcome, and Peek never closes c,
// so the caller can still serve the connection or close the Conn. The error
// is nil when m matched, ErrNoMatch when it ruled the connection out, and
// otherwise what stopped reading, such as ErrSniffTimeout or io.EOF.
//
// WithSniffTimeout, WithMaxSniffBytes and WithProxyProtocol apply; other
// options are ignored. Silent works as in a Mux. Peek sets read deadlines on
// c while reading and clears them before it returns.
func Peek(c net.Conn, m Matcher, opts ...Option) (*Conn, error) {
	if c == nil || m == nil {
		panic("portmux: Peek needs a connection and a matcher")
	}
	o := newOptions(opts)
	conn := &Conn{conn: c}
	s := newSniffer(conn, &o, time.Now())
	defer s.release()
	var tables atomic.Pointer[table]
	tables.Store(newTable(routeSet{routes: map[*Route]routeState{{}: {matchers: []Matcher{m}}}}))
	err := s.readProxyHeader(o.proxyPolicy, &tables)
	if err == nil {
		_, err = s.match(&tables, o.maxSniffBytes)
	}
	s.handOver(nil)
	return conn, err
}
