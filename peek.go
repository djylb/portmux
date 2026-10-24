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
	if c == nil || len(matchers) == 0 || slices.Contains(matchers, nil) {
		panic("portmux: PeekAny needs a connection and matchers")
	}
	all := make([]Option, len(opts))
	for i, opt := range opts {
		all[i] = opt
	}
	o := newOptions(all)
	conn := &Conn{conn: c}
	s := newSniffer(conn, &o, time.Now())
	defer s.release()
	var tables atomic.Pointer[table]
	t, routes := peekTable(matchers)
	tables.Store(t)
	err := s.readProxyHeader(proxyPolicyFor(&o, "", c), &tables)
	index := -1
	if err == nil {
		var r *Route
		if r, err = s.match(&tables, o.maxSniffBytes); err == nil {
			index = slices.Index(routes, r)
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
