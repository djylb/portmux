package httproute

import (
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// dump describes what match depends on: each host pattern's routes in
// order, and whether any route has an exact path or a regexp.
func dump(t *Table) string {
	var lines []string
	for pattern, list := range t.hosts.All() {
		names := make([]string, len(list))
		for i, rt := range list {
			names[i] = rt.name
		}
		lines = append(lines, fmt.Sprintf("%q: %s", pattern, strings.Join(names, " ")))
	}
	slices.Sort(lines)
	return fmt.Sprintf("routes %d levels %v\n%s", t.routes, t.levels > 0, strings.Join(lines, "\n"))
}

// model is a Config changed as With changes a Table.
type model struct {
	ups    map[string]Upstream
	routes []Route
}

func (m *model) config() Config {
	ups := slices.Collect(maps.Values(m.ups))
	return Config{Routes: slices.Clone(m.routes), Upstreams: ups}
}

func (m *model) clone() *model {
	return &model{ups: maps.Clone(m.ups), routes: slices.Clone(m.routes)}
}

func (m *model) apply(c Changes) {
	for _, name := range c.RemoveRoutes {
		m.routes = slices.DeleteFunc(m.routes, func(r Route) bool { return r.Name == name })
	}
	for _, name := range c.RemoveUpstreams {
		delete(m.ups, name)
	}
	for _, u := range c.Upstreams {
		m.ups[u.Name] = u
	}
	for _, r := range c.Routes {
		if i := slices.IndexFunc(m.routes, func(x Route) bool { return x.Name == r.Name }); i >= 0 {
			m.routes[i] = r
		} else {
			m.routes = append(m.routes, r)
		}
	}
}

func randomRoute(rng *rand.Rand, name string) Route {
	pick := func(xs ...string) string { return xs[rng.IntN(len(xs))] }
	r := Route{Name: name}
	for range rng.IntN(3) {
		r.Hosts = append(r.Hosts, pick("a.example", "A.example.", "*.example", ".b.example", "*", ""))
	}
	switch rng.IntN(6) {
	case 0:
		r.PathRegexp = pick("^/r[0-9]+$", "^/api/.*")
	case 1:
		r.Path, r.Exact = pick("/", "/api", "/api/v1"), true
	default:
		r.Path = pick("/", "/api", "/api/v1", "/x*", "/API")
	}
	r.CaseInsensitivePath = rng.IntN(4) == 0
	if rng.IntN(3) == 0 {
		r.Methods = []string{pick("GET", "POST")}
	}
	if rng.IntN(4) == 0 {
		v := rng.IntN(2) == 0
		r.TLS = &v
	}
	if rng.IntN(2) == 0 {
		r.Proxy = &Proxy{Upstream: "u" + strconv.Itoa(rng.IntN(4))}
	} else {
		r.Respond = okRespond
	}
	return r
}

func randomChanges(rng *rand.Rand) Changes {
	var c Changes
	for range rng.IntN(4) {
		name := "r" + strconv.Itoa(rng.IntN(24))
		if rng.IntN(3) == 0 {
			c.RemoveRoutes = append(c.RemoveRoutes, name)
		} else {
			c.Routes = append(c.Routes, randomRoute(rng, name))
		}
	}
	for range rng.IntN(2) {
		name := "u" + strconv.Itoa(rng.IntN(4))
		if rng.IntN(3) == 0 {
			c.RemoveUpstreams = append(c.RemoveUpstreams, name)
		} else {
			c.Upstreams = append(c.Upstreams, Upstream{Name: name, Dial: noDial, MaxKeys: 1 + rng.IntN(2)})
		}
	}
	return c
}

// valid reports whether With would accept c for m, as far as Build cannot
// tell: names to remove exist, no name repeats.
func (m *model) valid(c Changes) bool {
	names := map[string]bool{}
	for _, r := range m.routes {
		names[r.Name] = true
	}
	for _, n := range c.RemoveRoutes {
		if !names[n] {
			return false
		}
		delete(names, n)
	}
	for _, n := range c.RemoveUpstreams {
		if _, ok := m.ups[n]; !ok {
			return false
		}
	}
	seen := map[string]bool{}
	for _, r := range c.Routes {
		if seen[r.Name] {
			return false
		}
		seen[r.Name] = true
	}
	seen = map[string]bool{}
	for _, u := range c.Upstreams {
		if seen[u.Name] {
			return false
		}
		seen[u.Name] = true
	}
	return true
}

// TestWithEqualsBuild applies random changes with With and checks each
// result, and each refusal, against Build of the Config changed alike.
func TestWithEqualsBuild(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	for round := range 200 {
		m := &model{ups: map[string]Upstream{}}
		tbl, err := Build(m.config())
		if err != nil {
			t.Fatal(err)
		}
		for step := range 40 {
			c := randomChanges(rng)
			next, err := tbl.With(c)
			want := m.clone()
			want.apply(c)
			full, ferr := Build(want.config())
			if !m.valid(c) {
				if err == nil {
					t.Fatalf("round %d step %d: With accepted invalid changes %+v", round, step, c)
				}
				continue
			}
			if (err == nil) != (ferr == nil) {
				t.Fatalf("round %d step %d: With error %v, Build error %v", round, step, err, ferr)
			}
			if err != nil {
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("error %v does not wrap ErrInvalidConfig", err)
				}
				continue
			}
			if got, want := dump(next), dump(full); got != want {
				t.Fatalf("round %d step %d: With gives\n%s\nBuild gives\n%s", round, step, got, want)
			}
			before := dump(tbl)
			if _, err := tbl.With(randomChanges(rng)); err == nil && dump(tbl) != before {
				t.Fatal("With changed its receiver")
			}
			tbl, m = next, want
		}
	}
}

func TestWithErrors(t *testing.T) {
	tbl, err := Build(Config{
		Upstreams: []Upstream{{Name: "u", Dial: noDial}},
		Routes:    []Route{{Name: "a", Proxy: &Proxy{Upstream: "u"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Changes{
		"unnamed route":        {Routes: []Route{{Respond: okRespond}}},
		"unknown route":        {RemoveRoutes: []string{"x"}},
		"unknown upstream":     {RemoveUpstreams: []string{"x"}},
		"upstream in use":      {RemoveUpstreams: []string{"u"}},
		"route twice":          {Routes: []Route{{Name: "b", Respond: okRespond}, {Name: "b", Respond: okRespond}}},
		"proxy to removed":     {RemoveUpstreams: []string{"u"}, RemoveRoutes: []string{"a"}, Routes: []Route{{Name: "c", Proxy: &Proxy{Upstream: "u"}}}},
		"overlap":              {Routes: []Route{{Name: "b", Respond: okRespond}}},
		"bad upstream":         {Upstreams: []Upstream{{Name: "v"}}},
		"upstream twice":       {Upstreams: []Upstream{{Name: "v", Dial: noDial}, {Name: "v", Dial: noDial}}},
		"unknown proxy target": {Routes: []Route{{Name: "b", Path: "/b", Proxy: &Proxy{Upstream: "x"}}}},
	} {
		if _, err := tbl.With(c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Removing a route and its upstream together is fine.
	if _, err := tbl.With(Changes{RemoveRoutes: []string{"a"}, RemoveUpstreams: []string{"u"}}); err != nil {
		t.Error(err)
	}
}

// TestUpdateDiffsUpstreams checks that a Router updated with a Table that
// With changed keeps the transports of the upstreams left alone.
func TestUpdateDiffsUpstreams(t *testing.T) {
	t0, err := Build(Config{Upstreams: []Upstream{{Name: "a", Dial: noDial}, {Name: "b", Dial: noDial}}})
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{})
	defer func() { _ = r.Close() }()
	if err = r.Update(t0); err != nil {
		t.Fatal(err)
	}
	a, b := poolOf(r, "a"), poolOf(r, "b")
	t1, err := t0.With(Changes{Upstreams: []Upstream{{Name: "b", Dial: noDial, MaxKeys: 3}, {Name: "c", Dial: noDial}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Update(t1); err != nil {
		t.Fatal(err)
	}
	if poolOf(r, "a") != a || poolOf(r, "b") == b || poolOf(r, "c") == nil {
		t.Fatal("transports after a change of b and an addition of c")
	}
	t2, err := t1.With(Changes{RemoveUpstreams: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Update(t2); err != nil {
		t.Fatal(err)
	}
	if bd, _ := r.state.Load().upstreams.Get("a"); bd != nil || r.state.Load().upstreams.Len() != 2 {
		t.Fatal("a removed upstream kept its transports")
	}
}
