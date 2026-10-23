package portmux

import (
	"slices"
	"time"
)

// table is the installed configuration of a Mux's routes and what
// connections are matched against. It is never modified.
type table struct {
	routeSet
	// order lists every route in matching order, fallback routes last.
	order []*Route
	// byEntry holds the rules of each entry that a route is limited to, and
	// other those of every other entry.
	byEntry map[string]*ruleSet
	other   *ruleSet
	// fallbacks holds the fallback routes that some entry uses.
	fallbacks map[*Route]struct{}
}

// newTable builds the table of a configuration whose routes are in order,
// matching order, or sorts them for a nil order. Each route that can match is
// visited once per entry it applies to.
func newTable(s routeSet, order []*Route) *table {
	if order == nil {
		order = s.sorted()
	}
	t := &table{
		routeSet:  s,
		order:     order,
		byEntry:   make(map[string]*ruleSet),
		other:     &ruleSet{},
		fallbacks: make(map[*Route]struct{}),
	}
	for r, st := range s.routes {
		if !canMatch(r, st) {
			continue
		}
		for _, name := range st.entries {
			if t.byEntry[name] == nil {
				t.byEntry[name] = &ruleSet{}
			}
		}
	}
	for _, r := range t.order {
		st := s.routes[r]
		if !canMatch(r, st) {
			continue
		}
		var silences []time.Duration
		reportSilences(st.matchers, func(d time.Duration) { silences = append(silences, d) })
		if len(st.entries) > 0 {
			for _, name := range st.entries {
				t.byEntry[name].add(r, st, silences)
			}
			continue
		}
		t.other.add(r, st, silences)
		for _, rs := range t.byEntry {
			rs.add(r, st, silences)
		}
	}
	for _, rs := range t.byEntry {
		rs.finish(t)
	}
	t.other.finish(t)
	return t
}

// canMatch reports whether a route takes part in matching: a route without
// matchers or a resolver, other than a fallback, matches nothing and is only
// reached through resolvers.
func canMatch(r *Route, st routeState) bool {
	return r.fallback || st.resolve != nil || len(st.matchers) > 0
}

// orderAfter returns the routes of s, which a change made from those of t,
// in matching order: the routes whose priority is the same keep their order,
// and the others, which are few in a change, are sorted in between them.
func (t *table) orderAfter(s *routeSet, added []*Route) []*Route {
	kept := make([]rankedRoute, 0, len(s.routes))
	var moved []rankedRoute
	for _, r := range t.order {
		st, ok := s.routes[r]
		switch {
		case !ok:
		case st.priority == t.routes[r].priority:
			kept = append(kept, rankedRoute{r, st.priority})
		default:
			moved = append(moved, rankedRoute{r, st.priority})
		}
	}
	for _, r := range added {
		if st, ok := s.routes[r]; ok {
			moved = append(moved, rankedRoute{r, st.priority})
		}
	}
	if len(kept)+len(moved) != len(s.routes) {
		return s.sorted()
	}
	slices.SortFunc(moved, compareRanked)
	order := make([]*Route, 0, len(s.routes))
	for len(kept) > 0 || len(moved) > 0 {
		if len(moved) == 0 || len(kept) > 0 && compareRanked(kept[0], moved[0]) < 0 {
			order, kept = append(order, kept[0].r), kept[1:]
		} else {
			order, moved = append(order, moved[0].r), moved[1:]
		}
	}
	return order
}

// forEntry returns the rules for connections of an entry.
func (t *table) forEntry(name string) *ruleSet {
	if rs, ok := t.byEntry[name]; ok {
		return rs
	}
	return t.other
}

// ruleSet is what connections of one entry are matched against.
type ruleSet struct {
	rules []rule
	// fallback is the fallback route in use, or nil.
	fallback *Route
	// silences lists, in increasing order, the times after accepting at
	// which silent connections are checked.
	silences []time.Duration
}

type rule struct {
	route    *Route
	matchers []Matcher
	resolve  ResolveFunc // of the route, when it is a resolver route
}

// add appends a route that can match, added in matching order. The first
// fallback route is the one in use.
func (rs *ruleSet) add(r *Route, st routeState, silences []time.Duration) {
	if r.fallback {
		if rs.fallback == nil {
			rs.fallback = r
		}
		return
	}
	rs.rules = append(rs.rules, rule{route: r, matchers: st.matchers, resolve: st.resolve})
	for _, d := range silences {
		if !slices.Contains(rs.silences, d) {
			rs.silences = append(rs.silences, d)
		}
	}
}

func (rs *ruleSet) finish(t *table) {
	slices.Sort(rs.silences)
	if rs.fallback != nil {
		t.fallbacks[rs.fallback] = struct{}{}
	}
}

// evaluate returns the first route that is not ruled out yet, if it matches.
// Routes that cannot match any more are marked in dead.
// It returns the route that takes the connection and the route that decided,
// which differ for a resolver.
func (rs *ruleSet) evaluate(dead []bool, in *Input) (target, via *Route, res Result) {
	for i := range rs.rules {
		if dead[i] {
			continue
		}
		e := &rs.rules[i]
		switch r, res := e.decide(in); res {
		case Match:
			return r, e.route, Match
		case NeedMore:
			if !in.final {
				return nil, nil, NeedMore
			}
		case NoMatch:
		}
		// The rule cannot match any more.
		dead[i] = true
	}
	return nil, nil, NoMatch
}

// evaluateSilent returns the first route that accepts a silent connection.
// Routes that still need bytes do not hold the later ones back.
func (rs *ruleSet) evaluateSilent(dead []bool, in *Input) (target, via *Route) {
	for i := range rs.rules {
		if dead[i] {
			continue
		}
		e := &rs.rules[i]
		if r, res := e.decide(in); res == Match {
			return r, e.route
		}
	}
	return nil, nil
}

// decide runs the rule's matchers and then, for a resolver route whose
// matchers matched or that has none, its resolver.
func (e *rule) decide(in *Input) (*Route, Result) {
	resolve := e.resolve
	if resolve == nil {
		return e.route, matchAny(e.matchers, in)
	}
	if len(e.matchers) > 0 {
		if res := matchAny(e.matchers, in); res != Match {
			return nil, res
		}
	}
	r, res := resolve(in)
	switch res {
	case Match:
		if r == nil {
			r = e.route
		}
		return r, Match
	case NeedMore:
		return nil, NeedMore
	default: // NoMatch, and results that a resolver must not return
		return nil, NoMatch
	}
}
