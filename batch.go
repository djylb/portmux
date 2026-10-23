package portmux

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"time"
)

var (
	errNilRoute       = fmt.Errorf("%w: nil route", ErrInvalidRoute)
	errForeignRoute   = fmt.Errorf("%w: the route belongs to another Mux", ErrInvalidRoute)
	errBatchDone      = errors.New("portmux: Batch used after it returned")
	errFallbackConfig = fmt.Errorf("%w: a fallback route has no matchers", ErrInvalidRoute)
	errResolveConfig  = fmt.Errorf("%w: a resolver route neither rejects nor falls back", ErrInvalidRoute)
	errHandlerConfig  = fmt.Errorf("%w: a reject route has no handler", ErrInvalidRoute)
	errNilMatcher     = fmt.Errorf("%w: nil matcher", ErrInvalidRoute)
	errMaxConnsConfig = fmt.Errorf("%w: negative MaxConns", ErrInvalidRoute)
	errUpsertName     = fmt.Errorf("%w: Upsert of a route without a name", ErrInvalidRoute)
)

// Batch collects route changes that a Mux applies together: a connection is
// matched either against the routes before every change or after all of them.
// A Batch is only valid during the function passed to Mux.Batch.
type Batch struct {
	m     *Mux
	base  *table   // the table that view was taken from
	view  routeSet // the routes as they will be if the batch is applied
	ops   []func(*routeSet) error
	added []*Route
	done  bool
}

// routeSet is the configuration of a Mux's routes. An installed routeSet is
// never modified: changes are made to a copy.
type routeSet struct {
	routes map[*Route]routeState
	names  map[string]*Route
}

// routeState is the part of a route's configuration that can change.
type routeState struct {
	priority int
	matchers []Matcher
	entries  []string
	maxConns int
	// dispatchTimeout and maxQueued override the entry's settings when
	// not zero.
	dispatchTimeout time.Duration
	maxQueued       int
	resolve         ResolveFunc
	handler         func(*Conn)
}

func (s *routeSet) clone() routeSet {
	c := routeSet{routes: make(map[*Route]routeState, len(s.routes)), names: make(map[string]*Route, len(s.names))}
	maps.Copy(c.routes, s.routes)
	maps.Copy(c.names, s.names)
	return c
}

// Batch calls fn with a Batch and applies its changes atomically when fn
// returns nil. When fn returns an error, nothing is applied and the routes it
// added are closed. After Close, Batch applies nothing and returns
// net.ErrClosed.
//
// fn works on a snapshot of the routes and holds no lock, so it may call
// other methods of the Mux. Its changes are applied on top of the routes as
// they are when fn returns; when a change no longer applies, for example
// because another goroutine removed the route meanwhile, Batch applies
// nothing and returns the error.
func (m *Mux) Batch(fn func(b *Batch) error) error {
	base := m.table.Load()
	b := &Batch{m: m, base: base, view: base.clone()}
	err := fn(b)
	b.done = true
	var removed []*Route
	if err == nil {
		removed, err = m.apply(b)
	}
	if err != nil {
		// Routes of a batch not applied, such as one on a closed Mux, are
		// closed at once.
		for _, r := range b.added {
			r.closeListener()
		}
		return err
	}
	// The new table is published before removed listeners close, so
	// connections that were waiting for them are matched without them.
	for _, r := range removed {
		r.closeListener()
	}
	return nil
}

// do applies op to the batch's view and records it for the commit.
func (b *Batch) do(op func(*routeSet) error) error {
	if b.done {
		return errBatchDone
	}
	if err := op(&b.view); err != nil {
		return err
	}
	b.ops = append(b.ops, op)
	return nil
}

// checkConfig reports why cfg is not a valid route, or nil.
func checkConfig(cfg RouteConfig) error {
	if err := checkMatchers(cfg.Matchers); err != nil {
		return err
	}
	switch {
	case cfg.Fallback && len(cfg.Matchers) > 0:
		return errFallbackConfig
	case cfg.Resolve != nil && (cfg.Reject || cfg.Fallback):
		return errResolveConfig
	case cfg.Handler != nil && cfg.Reject:
		return errHandlerConfig
	case cfg.MaxConns < 0:
		return errMaxConnsConfig
	}
	return nil
}

// stateOf returns the changeable settings of cfg.
func stateOf(cfg RouteConfig) routeState {
	return routeState{priority: cfg.Priority, matchers: slices.Clone(cfg.Matchers), entries: entryList(cfg.Entries), maxConns: cfg.MaxConns,
		dispatchTimeout: cfg.DispatchTimeout, maxQueued: cfg.MaxQueued, resolve: cfg.Resolve, handler: cfg.Handler}
}

// Add adds a route.
func (b *Batch) Add(cfg RouteConfig) (*Route, error) {
	if b.done {
		return nil, errBatchDone
	}
	if err := checkConfig(cfg); err != nil {
		return nil, err
	}
	r := &Route{
		mux:      b.m,
		name:     cfg.Name,
		seq:      b.m.seq.Add(1),
		ch:       make(chan *Conn),
		done:     make(chan struct{}),
		reject:   cfg.Reject,
		fallback: cfg.Fallback,
	}
	st := stateOf(cfg)
	err := b.do(func(s *routeSet) error {
		if r.name != "" {
			if _, ok := s.names[r.name]; ok {
				return fmt.Errorf("%w: %q", ErrDuplicateName, r.name)
			}
			s.names[r.name] = r
		}
		s.routes[r] = st
		return nil
	})
	if err != nil {
		r.closeListener()
		return nil, err
	}
	b.added = append(b.added, r)
	return r, nil
}

// SetMatchers replaces the matchers of r.
func (b *Batch) SetMatchers(r *Route, matchers ...Matcher) error {
	if err := b.check(r); err != nil {
		return err
	}
	if err := checkMatchers(matchers); err != nil {
		return err
	}
	if r.fallback && len(matchers) > 0 {
		return errFallbackConfig
	}
	ms := slices.Clone(matchers)
	return b.update(r, func(st *routeState) { st.matchers = ms })
}

// SetEntries limits r to connections of the entries, or lets it apply to
// every entry when none are given.
func (b *Batch) SetEntries(r *Route, entries ...string) error {
	list := entryList(entries)
	return b.update(r, func(st *routeState) { st.entries = list })
}

// entryList copies entries without duplicates, or returns nil for none.
func entryList(entries []string) []string {
	var list []string
	for _, e := range entries {
		if !slices.Contains(list, e) {
			list = append(list, e)
		}
	}
	return list
}

// SetMaxConns changes the limit of open connections of r; see
// RouteConfig.MaxConns. Open connections over a lowered limit stay open.
func (b *Batch) SetMaxConns(r *Route, n int) error {
	if n < 0 {
		return errMaxConnsConfig
	}
	return b.update(r, func(st *routeState) { st.maxConns = n })
}

// SetDispatchTimeout changes the dispatch timeout of r; see
// RouteConfig.DispatchTimeout.
func (b *Batch) SetDispatchTimeout(r *Route, d time.Duration) error {
	return b.update(r, func(st *routeState) { st.dispatchTimeout = d })
}

// SetMaxQueued changes the limit of queued connections of r; see
// RouteConfig.MaxQueued.
func (b *Batch) SetMaxQueued(r *Route, n int) error {
	return b.update(r, func(st *routeState) { st.maxQueued = n })
}

// SetHandler changes the handler of r, or turns r into a route that
// delivers to Accept with nil; see RouteConfig.Handler. Connections that
// already wait for Accept stay there.
func (b *Batch) SetHandler(r *Route, handler func(*Conn)) error {
	if err := b.check(r); err != nil {
		return err
	}
	if handler != nil && r.reject {
		return errHandlerConfig
	}
	return b.update(r, func(st *routeState) { st.handler = handler })
}

// SetResolve changes the resolver of r, or removes it with nil; see
// RouteConfig.Resolve.
func (b *Batch) SetResolve(r *Route, resolve ResolveFunc) error {
	if err := b.check(r); err != nil {
		return err
	}
	if resolve != nil && (r.reject || r.fallback) {
		return errResolveConfig
	}
	return b.update(r, func(st *routeState) { st.resolve = resolve })
}

// Upsert adds the route named cfg.Name, or changes the route of that name to
// cfg, keeping the route and its listener, so that a server in its Accept
// goes on serving it: reloading a configuration route by route closes no
// listener of a route that stays. A route whose Reject or Fallback changes is
// a different kind of route: Upsert replaces it, closing the old one, whose
// connections waiting for Accept are matched again. cfg.Name must not be
// empty.
func (b *Batch) Upsert(cfg RouteConfig) (*Route, error) {
	if b.done {
		return nil, errBatchDone
	}
	if cfg.Name == "" {
		return nil, errUpsertName
	}
	if err := checkConfig(cfg); err != nil {
		return nil, err
	}
	r := b.view.names[cfg.Name]
	if r == nil {
		return b.Add(cfg)
	}
	if r.reject != cfg.Reject || r.fallback != cfg.Fallback {
		if err := b.Remove(r); err != nil {
			return nil, err
		}
		return b.Add(cfg)
	}
	st := stateOf(cfg)
	if err := b.update(r, func(cur *routeState) { *cur = st }); err != nil {
		return nil, err
	}
	return r, nil
}

// SetPriority changes the priority of r.
func (b *Batch) SetPriority(r *Route, priority int) error {
	return b.update(r, func(st *routeState) { st.priority = priority })
}

// update records a change to the configuration of r.
func (b *Batch) update(r *Route, change func(*routeState)) error {
	if err := b.check(r); err != nil {
		return err
	}
	return b.do(func(s *routeSet) error {
		st, ok := s.routes[r]
		if !ok {
			return net.ErrClosed
		}
		change(&st)
		s.routes[r] = st
		return nil
	})
}

// Remove removes r and closes its listener once the batch is applied.
func (b *Batch) Remove(r *Route) error {
	if err := b.check(r); err != nil {
		return err
	}
	return b.do(func(s *routeSet) error {
		if _, ok := s.routes[r]; !ok {
			return net.ErrClosed
		}
		delete(s.routes, r)
		if r.name != "" {
			delete(s.names, r.name)
		}
		return nil
	})
}

// Route returns the route with the given name, including changes made in
// this batch, or nil.
func (b *Batch) Route(name string) *Route {
	if b.done {
		return nil
	}
	return b.view.names[name]
}

// Routes returns the routes in the order they would be matched if the batch
// were applied now, fallback routes last. It previews where a new route
// lands; return an error from the batch function to drop the changes.
func (b *Batch) Routes() []*Route {
	if b.done {
		return nil
	}
	return b.view.sorted()
}

func (b *Batch) check(r *Route) error {
	switch {
	case b.done:
		return errBatchDone
	case r == nil:
		return errNilRoute
	case r.mux != b.m:
		return errForeignRoute
	}
	return nil
}

func checkMatchers(matchers []Matcher) error {
	if slices.Contains(matchers, nil) {
		return errNilMatcher
	}
	return nil
}

// apply replays a batch's changes on the current routes and installs the
// result, or changes nothing when one of them fails. It returns the routes
// that the changes removed, including those the batch added and removed
// again, or net.ErrClosed when the Mux is closed.
func (m *Mux) apply(b *Batch) ([]*Route, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() {
		return nil, net.ErrClosed
	}
	cur := m.table.Load()
	s := b.view
	if cur != b.base {
		// Changed since the batch began: its changes apply to the routes as
		// they are now.
		s = cur.clone()
		for _, op := range b.ops {
			if err := op(&s); err != nil {
				return nil, err
			}
		}
	}
	var removed []*Route
	for r := range cur.routes {
		if _, ok := s.routes[r]; !ok {
			removed = append(removed, r)
		}
	}
	for _, r := range b.added {
		if _, ok := s.routes[r]; !ok {
			removed = append(removed, r)
		}
	}
	m.table.Store(newTable(s, cur.orderAfter(&s, b.added)))
	return removed, nil
}

// sorted returns the routes in matching order: by priority, highest first,
// then in the order they were added, with fallback routes last.
func (s *routeSet) sorted() []*Route {
	// The priorities are copied out, so that comparisons look nothing up.
	list := make([]rankedRoute, 0, len(s.routes))
	for r, st := range s.routes {
		list = append(list, rankedRoute{r, st.priority})
	}
	slices.SortFunc(list, compareRanked)
	routes := make([]*Route, len(list))
	for i, e := range list {
		routes[i] = e.r
	}
	return routes
}

// rankedRoute is a route with its priority, for sorting.
type rankedRoute struct {
	r        *Route
	priority int
}

// compareRanked orders routes by priority, highest first, then in the order
// they were added, with fallback routes last.
func compareRanked(a, b rankedRoute) int {
	if a.r.fallback != b.r.fallback {
		if a.r.fallback {
			return 1
		}
		return -1
	}
	if c := cmp.Compare(b.priority, a.priority); c != 0 {
		return c
	}
	return cmp.Compare(a.r.seq, b.r.seq)
}
