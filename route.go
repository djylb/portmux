package portmux

import (
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// RouteConfig describes a route for Mux.Add and Batch.Add.
type RouteConfig struct {
	// Resolve lets your code choose the route, from everything known about
	// the connection; see ResolveFunc. A resolver route is one rule among
	// the others: it is tried in priority order, and its Matchers, if any,
	// are conditions that must match before the resolver is asked, as in
	// "TLS from the office, then look the name up".
	Resolve ResolveFunc
	// Name identifies the route for Mux.Route and Batch.Route. It is
	// optional. A non-empty name must be unique within the Mux.
	Name string
	// Entries limits the route to connections of these entries; see Entry.
	// Without entries the route applies to every entry, which suits rules
	// such as block lists; a global route that waits for bytes also holds
	// back the later routes of every entry, so give such routes entries or a
	// lower priority than the routes of dedicated entries. Entries also bind
	// resolvers: a resolver that sends a connection to a route limited to
	// other entries gets it closed with ErrEntryMismatch.
	Entries []string
	// Matchers select the connections of the route; one of them matching is
	// enough. A route without matchers matches nothing, which pauses it while
	// its listener stays open.
	Matchers []Matcher
	// Priority orders the routes. Higher priorities are tried first, and
	// routes with equal priority in the order they were added.
	Priority int
	// Reject makes the route close the connections it matches, reported with
	// ErrRefused, instead of delivering them; its Accept never returns a
	// connection. With a high priority and address matchers it is a block
	// list that closes connections before reading from them. Matchers rule
	// out what they cannot parse or find ambiguous, such as a request with two
	// Host fields, so a reject route does not see it: where reject routes
	// guard the others, make the fallback a reject route too, with Fallback
	// and Reject, which closes whatever no other route took.
	Reject bool
	// Fallback makes the route take the connections that no other route
	// matched, after all of them, whatever their priorities: those every
	// route ruled out, and those that sent bytes but stayed undecided until
	// the sniff timeout. Clients that sent nothing are not taken; route them
	// with Silent. A fallback route has no matchers. Of several fallback
	// routes, the one with the highest priority is used and the others stand
	// by, so a replacement can be added before the old one is removed.
	Fallback bool
	// MaxConns limits the connections the route has open: delivered, or
	// waiting for Accept, and not closed yet. Connections over the limit are
	// closed and reported with ErrConnLimit. Zero means no limit; a negative
	// value is not valid.
	MaxConns int
	// DispatchTimeout and MaxQueued override WithDispatchTimeout and
	// WithMaxQueued for the route, so that a route whose server is
	// slow to accept can wait longer, or queue less, than the others of its
	// entry. Zero keeps the entry's setting, and a negative value removes the
	// limit. They do not apply to a route with a Handler.
	DispatchTimeout time.Duration
	MaxQueued       int
	// Handler, when set, serves the route's connections instead of Accept:
	// each matched connection is passed to it in the goroutine that matched
	// it, once it no longer counts as pending. This saves the accept loop,
	// the hand-over to it and the queue, so dispatch timeouts and
	// WithMaxQueued do not apply. The handler owns the connection and must
	// close it. A panic in the handler closes the connection and is
	// reported to the observer as a *PanicError, as one in a matcher is.
	// Accept of such a route never returns a connection.
	Handler func(c *Conn)
}

// ResolveFunc chooses the route of a connection in your own code, typically
// by looking up the ClientHello's SNI or the request's Host in a table of
// your own, which costs the same for any number of targets. It is called
// like a matcher, first before any byte arrives and then after every read,
// and returns:
//
//   - a route of the same Mux and Match: the connection goes to that route.
//     It may be a route without matchers, which serves only as a target for
//     resolvers, a reject route, which closes the connection, or nil for the
//     resolver route's own listener;
//   - NeedMore while it cannot decide yet, which holds the later routes back;
//   - NoMatch to leave the connection to the later routes.
//
// Its decisions must be final, as a matcher's are. It runs in the Mux's
// goroutines, must not block, and must not retain the Input. A connection it
// sends to a closed route is closed and reported with ErrRouteClosed, and one
// it sends to a route limited to other entries with ErrEntryMismatch.
type ResolveFunc func(in *Input) (*Route, Result)

// Route is a net.Listener for the connections matched by one route of a Mux.
// Its configuration can be changed while the Mux serves; the change applies
// to the next matching decision of every undelivered connection.
type Route struct {
	mux       *Mux
	name      string
	seq       uint64
	ch        chan *Conn
	done      chan struct{}
	once      sync.Once
	matched   atomic.Uint64
	queued    atomic.Int64
	accepting atomic.Int64
	open      atomic.Int64
	routeKind
}

// routeKind is the part of a route's configuration that cannot change: a
// route of another kind is a different route.
type routeKind struct {
	reject   bool
	fallback bool
}

// Accept waits for the next connection matched by the route. The connection
// is a *Conn. Routes that reject or have a handler deliver nothing to Accept,
// which then returns only when the route is closed.
func (r *Route) Accept() (net.Conn, error) {
	c, err := r.AcceptConn()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// AcceptConn is Accept with the concrete connection type.
func (r *Route) AcceptConn() (*Conn, error) {
	// A connection already waiting is taken without blocking, which only
	// locks the route's channel.
	select {
	case c := <-r.ch:
		return c, nil
	default:
	}
	r.accepting.Add(1)
	defer r.accepting.Add(-1)
	select {
	case c := <-r.ch:
		return c, nil
	case <-r.done:
		return nil, net.ErrClosed
	}
}

// Close removes the route from its Mux and closes the listener: Accept
// returns net.ErrClosed and the route stops matching. Connections that were
// matched to it but not accepted yet are matched again against the remaining
// routes. Closing a removed route does nothing.
func (r *Route) Close() error {
	err := r.mux.Batch(func(b *Batch) error { return b.Remove(r) })
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Addr returns the address of the listener that serves the route's entries.
// When several listeners serve them, it returns an address that lists them.
func (r *Route) Addr() net.Addr {
	return r.mux.addr(r.state().entries)
}

// Name returns the route's name.
func (r *Route) Name() string {
	return r.name
}

// Priority returns the route's current priority.
func (r *Route) Priority() int {
	return r.state().priority
}

// Matchers returns the route's current matchers.
func (r *Route) Matchers() []Matcher {
	return slices.Clone(r.state().matchers)
}

// Entries returns the entries the route is limited to, or nil when it applies
// to every entry.
func (r *Route) Entries() []string {
	return slices.Clone(r.state().entries)
}

// state returns the route's current configuration, which is zero once the
// route was removed.
func (r *Route) state() routeState {
	return r.mux.table.Load().routes[r]
}

// SetEntries limits the route to connections of the entries, or lets it apply
// to every entry when none are given. It returns net.ErrClosed for a removed
// route.
func (r *Route) SetEntries(entries ...string) error {
	return r.mux.Batch(func(b *Batch) error { return b.SetEntries(r, entries...) })
}

// Matched returns how many connections the route has matched. For a reject
// route these are the connections it closed.
func (r *Route) Matched() uint64 {
	return r.matched.Load()
}

// Reject reports whether the route closes the connections it matches.
func (r *Route) Reject() bool {
	return r.reject
}

// isClosed reports whether the route's listener is closed.
func (r *Route) isClosed() bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// Fallback reports whether the route takes connections that no route matched.
func (r *Route) Fallback() bool {
	return r.fallback
}

// SetMatchers replaces the route's matchers. Without matchers the route is
// paused: it matches nothing but its listener stays open. It returns
// net.ErrClosed for a removed route.
func (r *Route) SetMatchers(matchers ...Matcher) error {
	return r.mux.Batch(func(b *Batch) error { return b.SetMatchers(r, matchers...) })
}

// SetHandler changes the route's handler; see Batch.SetHandler. It returns
// net.ErrClosed for a removed route.
func (r *Route) SetHandler(handler func(*Conn)) error {
	return r.mux.Batch(func(b *Batch) error { return b.SetHandler(r, handler) })
}

// SetResolve changes the route's resolver; see Batch.SetResolve. It returns
// net.ErrClosed for a removed route.
func (r *Route) SetResolve(resolve ResolveFunc) error {
	return r.mux.Batch(func(b *Batch) error { return b.SetResolve(r, resolve) })
}

// SetMaxConns changes the limit of open connections; see
// RouteConfig.MaxConns. It returns net.ErrClosed for a removed route.
func (r *Route) SetMaxConns(n int) error {
	return r.mux.Batch(func(b *Batch) error { return b.SetMaxConns(r, n) })
}

// MaxConns returns the route's limit of open connections, or zero.
func (r *Route) MaxConns() int {
	return r.state().maxConns
}

// SetDispatchTimeout changes the route's dispatch timeout; see
// RouteConfig.DispatchTimeout. It applies to connections matched from then
// on, and returns net.ErrClosed for a removed route.
func (r *Route) SetDispatchTimeout(d time.Duration) error {
	return r.mux.Batch(func(b *Batch) error { return b.SetDispatchTimeout(r, d) })
}

// SetMaxQueued changes the route's limit of queued connections; see
// RouteConfig.MaxQueued. Connections already queued stay queued. It returns
// net.ErrClosed for a removed route.
func (r *Route) SetMaxQueued(n int) error {
	return r.mux.Batch(func(b *Batch) error { return b.SetMaxQueued(r, n) })
}

// tryOpen counts a connection as open unless max, when positive, are open.
func (r *Route) tryOpen(max int) bool {
	return addBelow(&r.open, max)
}

// SetPriority changes the route's priority. It returns net.ErrClosed for a
// removed route.
func (r *Route) SetPriority(priority int) error {
	return r.mux.Batch(func(b *Batch) error { return b.SetPriority(r, priority) })
}

// RouteInfo describes the state of a route at one moment.
type RouteInfo struct {
	Name     string
	Priority int
	// Entries lists the entries the route is limited to, or is nil.
	Entries []string
	// Matchers describes the matchers, as in TLS(SNI("a.example")).
	Matchers []string
	Reject   bool
	Fallback bool
	// Resolver reports a route that chooses routes with a ResolveFunc.
	Resolver bool
	// Handler reports a route whose connections go to a handler.
	Handler bool
	// Active reports whether the route is tried now: it was not removed and
	// has matchers or a resolver, or it is the fallback route in use. Routes
	// without matchers are not tried but still take what resolvers send them.
	Active bool
	// Removed reports whether the route was closed or removed.
	Removed bool
	// Matched counts the connections the route has matched.
	Matched uint64
	// Queued is the number of matched connections waiting for Accept.
	Queued int64
	// Open is the number of connections the route has open: delivered, or
	// waiting for Accept, and not closed yet.
	Open int64
	// MaxConns is the limit of Open, or zero.
	MaxConns int
	// DispatchTimeout and MaxQueued are the route's own settings, or zero;
	// see RouteConfig.
	DispatchTimeout time.Duration
	MaxQueued       int
	// Accepting is the number of Accept calls waiting for a connection. A
	// route without a handler whose Accepting stays zero has no server taking
	// its connections.
	Accepting int64
}

// Info returns the current state of the route.
func (r *Route) Info() RouteInfo {
	return r.info(r.mux.table.Load())
}

func (r *Route) info(t *table) RouteInfo {
	st, present := t.routes[r]
	info := RouteInfo{
		Name:      r.name,
		Priority:  st.priority,
		Entries:   slices.Clone(st.entries),
		Matchers:  make([]string, len(st.matchers)),
		Reject:    r.reject,
		Fallback:  r.fallback,
		Resolver:  st.resolve != nil,
		Handler:   st.handler != nil,
		Removed:   !present,
		Matched:   r.matched.Load(),
		Queued:    r.queued.Load(),
		Open:      r.open.Load(),
		MaxConns:  st.maxConns,
		Accepting: r.accepting.Load(),

		DispatchTimeout: st.dispatchTimeout,
		MaxQueued:       st.maxQueued,
	}
	for i, m := range st.matchers {
		info.Matchers[i] = describe(m)
	}
	switch {
	case r.fallback:
		_, info.Active = t.fallbacks[r]
	case st.resolve != nil:
		info.Active = present
	default:
		info.Active = present && len(st.matchers) > 0
	}
	return info
}

func (r *Route) closeListener() {
	r.once.Do(func() { close(r.done) })
}
