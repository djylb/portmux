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

// newTable builds the table of a configuration. Each route is visited once
// per entry it applies to.
func newTable(s routeSet) *table {
	t := &table{
		routeSet:  s,
		order:     s.sorted(),
		byEntry:   make(map[string]*ruleSet),
		other:     &ruleSet{},
		fallbacks: make(map[*Route]struct{}),
	}
	for _, st := range s.routes {
		for _, name := range st.entries {
			if t.byEntry[name] == nil {
				t.byEntry[name] = &ruleSet{}
			}
		}
	}
	for _, r := range t.order {
		st := s.routes[r]
		var silences []time.Duration
		reportSilences(st.matchers, func(d time.Duration) { silences = append(silences, d) })
		if len(st.entries) > 0 {
			for _, name := range st.entries {
				t.byEntry[name].add(r, st.matchers, silences)
			}
			continue
		}
		t.other.add(r, st.matchers, silences)
		for _, rs := range t.byEntry {
			rs.add(r, st.matchers, silences)
		}
	}
	for _, rs := range t.byEntry {
		rs.finish(t)
	}
	t.other.finish(t)
	return t
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
}

// add appends a route, added in matching order. The first fallback route is
// the one in use.
func (rs *ruleSet) add(r *Route, matchers []Matcher, silences []time.Duration) {
	if r.fallback {
		if rs.fallback == nil {
			rs.fallback = r
		}
		return
	}
	rs.rules = append(rs.rules, rule{route: r, matchers: matchers})
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
	resolve := e.route.resolve
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
