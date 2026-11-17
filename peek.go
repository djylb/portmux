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
// The options are those of the sniffing: WithSniffTimeout, WithMaxSniffBytes
// and WithProxyProtocol. Silent works as in a Mux. Peek sets read deadlines
// on c while reading and clears them before it returns.
func Peek(c net.Conn, m Matcher, opts ...PeekOption) (*Conn, error) {
	if m == nil {
		panic("portmux: Peek needs a matcher")
	}
	conn, _, err := PeekAny(c, []Matcher{m}, opts...)
	return conn, err
}

// PeekAny is Peek for several matchers, tried in order as the routes of a
// Mux are: it returns the index of the first that matches, or -1 with an
// error, so that a server learns which protocol the client speaks, as in
// PeekAny(c, []Matcher{TLS(), HTTP1(), SSH()}). A matcher that still needs
// bytes holds back the later ones, as a route does, and Silent among them
// works as in a Mux. PeekAny panics without a connection, without matchers
// or on a nil one, as Peek does.
func PeekAny(c net.Conn, matchers []Matcher, opts ...PeekOption) (*Conn, int, error) {
	if c == nil {
		panic("portmux: PeekAny needs a connection and matchers")
	}
	return NewPeeker(matchers, opts...).Peek(c)
}

// Peeker is PeekAny with its matchers and options prepared once, for a
// server that peeks at every connection it takes the same way. A Peeker is
// safe for concurrent use.
type Peeker struct {
	tables atomic.Pointer[table] // set once; as a Mux holds its table
	routes []*Route
	opts   options
}

// NewPeeker prepares matchers and opts for Peeker.Peek. It panics without
// matchers or on a nil one.
func NewPeeker(matchers []Matcher, opts ...PeekOption) *Peeker {
	if len(matchers) == 0 || slices.Contains(matchers, nil) {
		panic("portmux: PeekAny needs a connection and matchers")
	}
	all := make([]Option, len(opts))
	for i, opt := range opts {
		all[i] = opt
	}
	p := &Peeker{opts: newOptions(all)}
	t, routes := peekTable(matchers)
	p.tables.Store(t)
	p.routes = routes
	return p
}

// Peek is PeekAny with the matchers and options of p. It panics without a
// connection.
func (p *Peeker) Peek(c net.Conn) (*Conn, int, error) {
	if c == nil {
		panic("portmux: Peek needs a connection")
	}
	o := &p.opts
	conn := &Conn{conn: c}
	s := newSniffer(conn, o, time.Now())
	defer s.release()
	err := s.readProxyHeader(proxyPolicyFor(o, "", c), &p.tables)
	index := -1
	if err == nil {
		var r *Route
		if r, err = s.match(&p.tables, o.maxSniffBytes); err == nil {
			index = slices.Index(p.routes, r)
		}
	}
	s.handOver(nil)
	conn.dropEmpty()
	return conn, index, err
}

// peekTable returns a table with a rule of each matcher, in order, and the
// routes of the rules, which deliver nowhere; it is built without the
// configuration that a Mux keeps.
func peekTable(matchers []Matcher) (*table, []*Route) {
	rs := &ruleSet{}
	routes := make([]*Route, len(matchers))
	for i, m := range matchers {
		routes[i] = new(Route)
		rs.add(routes[i], routeState{matchers: []Matcher{m}}, nil)
	}
	add := rs.addSilence
	for _, r := range rs.rules {
		reportSilences(r.matchers, add)
	}
	t := &table{other: rs}
	rs.finish(t)
	return t, routes
}
