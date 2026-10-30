package httproute

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/djylb/netx/httprewrite"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
)

var okRespond = &Respond{Body: []byte("ok")}

func noDial(context.Context, DialInfo) (net.Conn, error) { return nil, errors.New("no backend") }

func TestBuildErrors(t *testing.T) {
	up := []Upstream{{Name: "b", Dial: noDial}}
	to := httprewrite.MustCompile("/x", nil)
	for name, c := range map[string]Config{
		"no action":         {Routes: []Route{{}}},
		"two actions":       {Routes: []Route{{Respond: okRespond, Redirect: &Redirect{To: to}}}},
		"unknown upstream":  {Routes: []Route{{Proxy: &Proxy{Upstream: "x"}}}, Upstreams: up},
		"duplicate route":   {Routes: []Route{{Name: "a", Respond: okRespond}, {Name: "a", Respond: okRespond}}},
		"duplicate up":      {Upstreams: []Upstream{up[0], up[0]}},
		"upstream no dial":  {Upstreams: []Upstream{{Name: "b"}}},
		"upstream no name":  {Upstreams: []Upstream{{Dial: noDial}}},
		"relative path":     {Routes: []Route{{Path: "api", Respond: okRespond}}},
		"unclean path":      {Routes: []Route{{Path: "/a/../b", Respond: okRespond}}},
		"bad host":          {Routes: []Route{{Hosts: []string{"a@b.com"}, Respond: okRespond}}},
		"bad method":        {Routes: []Route{{Methods: []string{"GE T"}, Respond: okRespond}}},
		"bad header":        {Routes: []Route{{Headers: []HeaderMatch{{Name: "X:Y"}}, Respond: okRespond}}},
		"redirect status":   {Routes: []Route{{Redirect: &Redirect{To: to, Status: 200}}}},
		"redirect no to":    {Routes: []Route{{Redirect: &Redirect{}}}},
		"respond status":    {Routes: []Route{{Respond: &Respond{Status: 99}}}},
		"error page status": {ErrorPages: map[int]ErrorPage{200: {}}},
		"request rules":     {Routes: []Route{{Respond: okRespond, RequestHeaders: []httprewrite.Rule{{Name: "X"}}}}},
		"replace path":      {Routes: []Route{{Proxy: &Proxy{Upstream: "b", ReplacePath: "x"}}}, Upstreams: up},
		"https status":      {Routes: []Route{{Respond: okRespond, RedirectHTTPS: &HTTPSRedirect{Status: 200}}}},
		"negative body":     {Routes: []Route{{Respond: okRespond, MaxRequestBody: -1}}},
		"same match":        {Routes: []Route{{Hosts: []string{"a.com"}, Path: "/x", Respond: okRespond}, {Hosts: []string{"A.com."}, Path: "/x", Respond: okRespond}}},
		"same as no hosts":  {Routes: []Route{{Respond: okRespond}, {Hosts: []string{"*"}, Respond: okRespond}}},
		"shadowed":          {Routes: []Route{{Path: "/x", Methods: []string{"GET", "POST"}, Respond: okRespond}, {Path: "/x", Methods: []string{"GET"}, Headers: []HeaderMatch{{Name: "A"}}, Respond: okRespond}}},
		"glob host":         {Routes: []Route{{Hosts: []string{"*a.com"}, Respond: okRespond}}},
		"mid wildcard":      {Routes: []Route{{Hosts: []string{"a.*.com"}, Respond: okRespond}}},
		"non-ascii host":    {Routes: []Route{{Hosts: []string{"bücher.de"}, Respond: okRespond}}},
		"exact star":        {Routes: []Route{{Path: "/a*", Exact: true, Respond: okRespond}}},
		"bad upgrade":       {Routes: []Route{{Respond: okRespond, Upgrades: []string{"a b"}}}},
		"nil wrap":          {Routes: []Route{{Respond: okRespond, Wrap: func(http.Handler) http.Handler { return nil }}}},
	} {
		if _, err := Build(c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMatchPrecedence(t *testing.T) {
	routes := []Route{
		{Name: "any", Respond: okRespond},
		{Name: "wild-root", Hosts: []string{"*.example.com"}, Respond: okRespond},
		{Name: "exact-root", Hosts: []string{"a.example.com"}, Respond: okRespond},
		{Name: "wild-api", Hosts: []string{"*.example.com"}, Path: "/api", Respond: okRespond},
		{Name: "exact-api-post", Hosts: []string{"a.example.com"}, Path: "/api", Methods: []string{"POST"}, Respond: okRespond},
		{Name: "exact-api", Hosts: []string{"A.Example.com"}, Path: "/api", Respond: okRespond},
		{Name: "deep", Hosts: []string{"*.x.example.com"}, Path: "/api/v1/", Respond: okRespond},
		{Name: "dot", Hosts: []string{".d.example.com"}, Path: "/api", Respond: okRespond},
		{Name: "raw", Hosts: []string{"*.example.com"}, Path: "/img*", Respond: okRespond},
		{Name: "header", Hosts: []string{"h.example.com"}, Headers: []HeaderMatch{{Name: "x-env", Values: []string{"beta"}}}, Respond: okRespond},
		{Name: "header-any", Hosts: []string{"h.example.com"}, Headers: []HeaderMatch{{Name: "X-Env"}}, Respond: okRespond},
		{Name: "no-host", Hosts: []string{""}, Path: "/nohost", Respond: okRespond},
	}
	levels := append(slices.Clone(routes),
		Route{Name: "eq-wild", Hosts: []string{"*.example.com"}, Path: "/login", Exact: true, Respond: okRespond},
		Route{Name: "pre-login", Hosts: []string{"a.example.com"}, Path: "/login", Respond: okRespond},
		Route{Name: "re-a", Hosts: []string{"a.example.com"}, PathRegexp: `^/u/(\d+)$`, Respond: okRespond},
		Route{Name: "re-wild", Hosts: []string{"*.example.com"}, PathRegexp: `^/u/`, Respond: okRespond},
		Route{Name: "re-wild-2", Hosts: []string{"*.example.com"}, PathRegexp: `^/u/7`, Respond: okRespond},
	)
	plain, err := Build(Config{Routes: routes})
	if err != nil {
		t.Fatal(err)
	}
	tab, err := Build(Config{Routes: levels})
	if err != nil {
		t.Fatal(err)
	}
	type matchCase struct{ method, host, path, env, want string }
	cases := []matchCase{
		{"GET", "other.org", "/", "", "any"},
		{"GET", "b.example.com", "/", "", "wild-root"},
		{"GET", "a.example.com", "/", "", "exact-root"},
		{"GET", "a.example.com", "/apis", "", "exact-root"},
		{"GET", "b.example.com", "/api/x", "", "wild-api"},
		// Equal paths: the exact host wins, and of equal routes the first.
		{"GET", "a.example.com", "/api", "", "exact-api"},
		{"POST", "a.example.com", "/api", "", "exact-api-post"},
		// A longer path beats a more specific host.
		{"GET", "a.b.x.example.com", "/api/v1/x", "", "deep"},
		{"GET", "a.x.example.com", "/api/v1", "", "wild-api"},
		{"GET", "d.example.com", "/api", "", "dot"},
		{"GET", "e.d.example.com", "/api/z", "", "dot"},
		{"GET", "b.example.com", "/img2/a", "", "raw"},
		{"GET", "b.example.com", "/imgs", "", "raw"},
		{"GET", "h.example.com", "/", "beta", "header"},
		{"GET", "h.example.com", "/", "alpha", "header-any"},
		{"GET", "h.example.com", "/", "", "wild-root"},
		{"GET", "", "/nohost/a", "", "no-host"},
		{"GET", "", "/", "", "any"},
	}
	extra := []matchCase{
		// An exact path beats a prefix, also of a more specific host.
		{"GET", "a.example.com", "/login", "", "eq-wild"},
		{"GET", "a.example.com", "/login/x", "", "pre-login"},
		// A regexp beats prefixes; of regexps, the more specific host,
		// then the first.
		{"GET", "a.example.com", "/u/12", "", "re-a"},
		{"GET", "a.example.com", "/u/x", "", "re-wild"},
		{"GET", "b.example.com", "/u/7", "", "re-wild"},
		{"GET", "other.org", "/u/7", "", "any"},
	}
	for i, tc := range append(slices.Clone(cases), append(cases, extra...)...) {
		tab := tab
		if i < len(cases) {
			tab = plain
		}
		req := httptest.NewRequest(tc.method, "http://x"+tc.path, nil)
		if tc.env != "" {
			req.Header.Set("X-Env", tc.env)
		}
		p, err := httphead.CleanPath(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		rt := tab.match(hostmatch.NormalizeHost(tc.host), p, req, &reqState{})
		if rt == nil || rt.name != tc.want {
			got := "<nil>"
			if rt != nil {
				got = rt.name
			}
			t.Errorf("%s %s%s: %s, want %s", tc.method, tc.host, tc.path, got, tc.want)
		}
	}
}

func TestJoinPath(t *testing.T) {
	for _, tc := range []struct{ prefix, rest, want string }{
		{"/v2", "/users", "/v2/users"},
		{"/", "/users", "/users"},
		{"/v2/", "/users", "/v2/users"},
		{"/v2", "users", "/v2/users"},
		{"/v2", "", "/v2"},
		{"/v2", ";p", "/v2;p"},
	} {
		if got := joinPath(tc.prefix, tc.rest); got != tc.want {
			t.Errorf("joinPath(%q, %q) = %q, want %q", tc.prefix, tc.rest, got, tc.want)
		}
	}
}

// naiveMatch chooses a route by comparing every route with every other.
func naiveMatch(routes []Route, host, p string) string {
	patterns := func(r Route) []string {
		if len(r.Hosts) == 0 || slices.Contains(r.Hosts, "*") {
			return append(slices.Clone(r.Hosts), "*", "")
		}
		return r.Hosts
	}
	// The rank of each pattern that matches host, most specific first.
	var all hostmatch.Map[int]
	for _, r := range routes {
		for _, h := range patterns(r) {
			all.Set(h, 0)
		}
	}
	order := map[string]int{}
	for pat := range all.Matches(host) {
		order[pat] = len(order)
	}
	type best struct {
		name      string
		len, rank int
	}
	levels := [3]best{{len: -1}, {len: -1}, {len: -1}}
	for _, r := range routes {
		rank := -1
		for _, h := range patterns(r) {
			var one hostmatch.Map[int]
			one.Set(h, 0)
			for pat := range one.Matches(host) {
				if rank < 0 || order[pat] < rank {
					rank = order[pat]
				}
			}
		}
		if rank < 0 {
			continue
		}
		path := cmpOr(r.Path, "/")
		level, l := 2, 2*len(path)+1 // a prefix of segments before one of bytes
		switch {
		case r.Exact:
			if p != path {
				continue
			}
			level, l = 0, 0
		case r.PathRegexp != "":
			if !regexp.MustCompile(r.PathRegexp).MatchString(p) {
				continue
			}
			level, l = 1, 0
		case strings.HasSuffix(path, "*"):
			if !strings.HasPrefix(p, path[:len(path)-1]) {
				continue
			}
			l = 2 * (len(path) - 1)
		case !httphead.HasPathPrefix(p, path):
			continue
		}
		if b := &levels[level]; l > b.len || l == b.len && rank < b.rank {
			*b = best{r.Name, l, rank}
		}
	}
	for _, b := range levels {
		if b.name != "" {
			return b.name
		}
	}
	return ""
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// FuzzMatch compares the table's choice with naiveMatch.
func FuzzMatch(f *testing.F) {
	routes := []Route{
		{Name: "any", Respond: okRespond},
		{Name: "a", Hosts: []string{"a.ex"}, Respond: okRespond},
		{Name: "wa", Hosts: []string{"*.ex"}, Path: "/a", Respond: okRespond},
		{Name: "aa", Hosts: []string{"a.ex"}, Path: "/a", Respond: okRespond},
		{Name: "gab", Hosts: []string{".a.ex"}, Path: "/a/b", Respond: okRespond},
		{Name: "rawa", Hosts: []string{"*.ex"}, Path: "/a*", Respond: okRespond},
		{Name: "bb", Hosts: []string{"b.ex", "*.b.ex"}, Path: "/b/", Respond: okRespond},
		{Name: "star", Hosts: []string{"*"}, Path: "/a/b/c", Respond: okRespond},
		{Name: "none", Hosts: []string{""}, Path: "/b", Respond: okRespond},
	}
	levels := append(slices.Clone(routes),
		Route{Name: "eq", Hosts: []string{"*.ex"}, Path: "/a/b", Exact: true, Respond: okRespond},
		Route{Name: "eq-a", Hosts: []string{"a.ex"}, Path: "/b/", Exact: true, Respond: okRespond},
		Route{Name: "re", Hosts: []string{"*.a.ex"}, PathRegexp: `^/a/[bc]`, Respond: okRespond},
		Route{Name: "re-any", PathRegexp: `c$`, Respond: okRespond},
	)
	tables := map[*Table][]Route{}
	for _, rs := range [][]Route{routes, levels} {
		tab, err := Build(Config{Routes: rs})
		if err != nil {
			f.Fatal(err)
		}
		tables[tab] = rs
	}
	for _, s := range []string{"a.ex /a", "x.b.ex /b/c", "ab.ex /a/b/c", " /b", "a.ex /a/b;x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		host, p, _ := strings.Cut(s, " ")
		clean, err := httphead.CleanPath("/" + p)
		if err != nil {
			return
		}
		n := hostmatch.NormalizeHost(host)
		if !n.Valid() || hostmatch.Normalize(n.String()) != n {
			return // naiveMatch takes names as strings, which it prepares again
		}
		for tab, routes := range tables {
			got := ""
			if rt := tab.match(n, clean, httptest.NewRequest("GET", "/", nil), &reqState{}); rt != nil {
				got = rt.name
			}
			if want := naiveMatch(routes, n.String(), clean); got != want {
				t.Fatalf("%q %q: %q, want %q", n.String(), clean, got, want)
			}
		}
	})
}

// BenchmarkMatchPrefix matches on a table of prefixes alone, the common
// case: many exact hosts with a few paths, a wildcard and a catch-all.
func BenchmarkMatchPrefix(b *testing.B) {
	var routes []Route
	for i := range 1000 {
		h := fmt.Sprintf("h%d.example.com", i)
		routes = append(routes, Route{Hosts: []string{h}, Respond: okRespond},
			Route{Hosts: []string{h}, Path: "/api", Respond: okRespond})
	}
	routes = append(routes, Route{Hosts: []string{"*.example.com"}, Path: "/static", Respond: okRespond}, Route{Respond: okRespond})
	tab, err := Build(Config{Routes: routes})
	if err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/v1/items", nil)
	n := hostmatch.NormalizeHost("h500.example.com")
	rs := &reqState{}
	b.ReportAllocs()
	for b.Loop() {
		if tab.match(n, "/api/v1/items", req, rs) == nil {
			b.Fatal("no route")
		}
	}
}
