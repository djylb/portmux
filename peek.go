package portmux

import (
	"net"
	"slices"
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
	tables.Store(peekTable(m))
	err := s.readProxyHeader(proxyPolicyFor(&o, "", c), &tables)
	if err == nil {
		_, err = s.match(&tables, o.maxSniffBytes)
	}
	s.handOver(nil)
	conn.dropEmpty()
	return conn, err
}

// peekRoute is the route of the tables of Peek, which deliver nowhere.
var peekRoute = new(Route)

// peekTable returns a table with one rule of m, built without the
// configuration that a Mux keeps.
func peekTable(m Matcher) *table {
	rs := &ruleSet{rules: []rule{{route: peekRoute, matchers: []Matcher{m}}}}
	reportSilences(rs.rules[0].matchers, func(d time.Duration) {
		if !slices.Contains(rs.silences, d) {
			rs.silences = append(rs.silences, d)
		}
	})
	slices.Sort(rs.silences)
	return &table{other: rs}
}
