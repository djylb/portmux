package hostmatch

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestMapPrecedence(t *testing.T) {
	var m Map[string]
	for _, p := range []string{"*", "*.example.com", "*.api.example.com", "api-*.example.com", "a*.example.com", "WWW.Example.com.", "", "*-*.example.com"} {
		m.Set(p, p)
	}
	tests := []struct{ host, want string }{
		{"www.example.com", "WWW.Example.com."},    // exact, compared lowercased
		{"WWW.EXAMPLE.COM.", "WWW.Example.com."},   // normalized like the patterns
		{"x.api.example.com", "*.api.example.com"}, // the longer suffix
		{"api-1.example.com", "api-*.example.com"}, // more literal characters than *.example.com
		{"ab.example.com", "a*.example.com"},       // 13 literal characters against 12
		{"x-y.example.com", "*-*.example.com"},     // likewise
		{"b.example.com", "*.example.com"},
		{"api-x.api.example.com", "*.api.example.com"}, // the suffix has more literal characters
		{"example.com", "*"},                           // '*' takes at least one byte
		{"other.org", "*"},
		{"", ""},                 // no name
		{"a@b.example.com", "-"}, // never matches
	}
	for _, tt := range tests {
		v, pattern, ok := m.Lookup(tt.host)
		got := "-"
		if ok {
			got = v
			if p := parseHostPattern(v).String(); pattern != p {
				t.Errorf("%q: pattern %q, want %q", tt.host, pattern, p)
			}
		}
		if got != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
	if m.Len() != 8 {
		t.Fatalf("Len = %d", m.Len())
	}
	all := maps.Collect(m.All())
	if len(all) != 8 || all["www.example.com"] != "WWW.Example.com." || all["*.api.example.com"] != "*.api.example.com" {
		t.Fatalf("All = %v", all)
	}

	// Replacing keeps the count; deleting falls back to the next pattern.
	m.Set("*.example.com", "suffix")
	if v, ok := m.Get("*.EXAMPLE.com"); !ok || v != "suffix" || m.Len() != 8 {
		t.Fatalf("Get = %q, %v, Len %d", v, ok, m.Len())
	}
	for _, p := range []string{"api-*.example.com", "*.example.com", "*", "www.example.com"} {
		if !m.Delete(p) {
			t.Fatalf("Delete(%q) = false", p)
		}
	}
	if m.Delete("*") || m.Delete("nothing") || m.Len() != 4 {
		t.Fatalf("second Delete, Len %d", m.Len())
	}
	if v, _, _ := m.Lookup("api-1.example.com"); v != "a*.example.com" {
		t.Fatalf("after Delete: %q", v)
	}
	if _, _, ok := m.Lookup("other.org"); ok {
		t.Fatal("other.org matched after deleting *")
	}
	for _, p := range []string{"*", "api-*.example.com", "x.example.com"} {
		if _, ok := m.Get(p); ok {
			t.Fatalf("Get(%q) after Delete", p)
		}
	}
}

func TestMapConcurrent(t *testing.T) {
	var m Map[int]
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for i := range 200 {
				p := fmt.Sprintf("*.h%d-%d.example.com", w, i)
				m.Set(p, i)
				m.Set(fmt.Sprintf("x*.h%d-%d.example.com", w, i), i)
				if v, _, ok := m.Lookup(fmt.Sprintf("a.h%d-%d.example.com", w, i)); !ok || v != i {
					t.Errorf("Lookup = %d, %v", v, ok)
					return
				}
				if i%2 == 0 {
					m.Delete(p)
				}
			}
		})
	}
	wg.Wait()
	if m.Len() != 4*(200+100) {
		t.Fatalf("Len = %d", m.Len())
	}
}

func BenchmarkMapLookup(b *testing.B) {
	for _, n := range []int{10, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			var m Map[int]
			for i := range n {
				m.Set(fmt.Sprintf("h%d.example.com", i), i)
				m.Set(fmt.Sprintf("*.t%d.example.com", i), i)
			}
			m.Set("*", -1)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, _, ok := m.Lookup("a.b.t7.example.com"); !ok {
						b.Error("no match")
						return
					}
				}
			})
		})
	}
}

func TestMapMatches(t *testing.T) {
	var m Map[int]
	for i, p := range []string{"*", "*.example.com", "*.b.example.com", "a.b.example.com", "a*.example.com", "*-*.example.com", "*.com", "a.b.*.com", ""} {
		m.Set(p, i)
	}
	var got []string
	for pattern := range m.Matches("A.B.Example.COM.") {
		got = append(got, pattern)
	}
	want := []string{"a.b.example.com", "*.b.example.com", "a*.example.com", "*.example.com", "a.b.*.com", "*.com", "*"}
	if !slices.Equal(got, want) {
		t.Fatalf("Matches = %q, want %q", got, want)
	}
	// Stopping early stops the walk.
	n := 0
	for range m.Matches("x.example.com") {
		if n++; n == 2 {
			break
		}
	}
	if n != 2 {
		t.Fatalf("stopped after %d", n)
	}
	// No name matches the empty pattern only; invalid names match nothing.
	for host, want := range map[string][]string{"": {""}, "a@b.example.com": nil, "org": {"*"}} {
		got = nil
		for pattern := range m.Matches(host) {
			got = append(got, pattern)
		}
		if !slices.Equal(got, want) {
			t.Errorf("Matches(%q) = %q, want %q", host, got, want)
		}
	}
}

// FuzzMap checks Matches and Lookup against Set: every pattern that
// matches is yielded once, most specific first, and Lookup returns the first.
func FuzzMap(f *testing.F) {
	f.Add("*.example.com|a*.example.com|*-*.example.com|*|www.example.com", "a-b.example.com")
	f.Add("*.b.c|*.c|a.*.c|*c", "a.b.c")
	f.Fuzz(func(t *testing.T, patterns, host string) {
		var m Map[string]
		set := map[string]string{} // normalized pattern -> the last one set
		for _, p := range strings.Split(patterns, "|") {
			m.Set(p, p)
			set[parseHostPattern(p).String()] = p
		}
		var got []string
		for pattern, v := range m.Matches(host) {
			if parseHostPattern(v).String() != pattern {
				t.Fatalf("pattern %q with the value of %q", pattern, v)
			}
			got = append(got, pattern)
		}
		var want []string
		for norm, p := range set {
			if NewSet(p).Match(host) {
				want = append(want, norm)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("Matches(%q) = %q, matching patterns %q", host, got, want)
		}
		rank := func(p string) [3]int {
			switch {
			case p == "*":
				return [3]int{0, 0, 0}
			case !strings.Contains(p, "*"):
				return [3]int{2, 0, 0}
			}
			lit := len(p) - strings.Count(p, "*")
			suffix := 0
			if strings.HasPrefix(p, "*.") && !strings.Contains(p[2:], "*") {
				suffix = 1
			}
			return [3]int{1, lit, suffix}
		}
		for i := 1; i < len(got); i++ {
			a, b := rank(got[i-1]), rank(got[i])
			if slices.Compare(a[:], b[:]) < 0 {
				t.Fatalf("Matches(%q) = %q: %q before %q", host, got, got[i-1], got[i])
			}
		}
		v, pattern, ok := m.Lookup(host)
		if ok != (len(got) > 0) || ok && (pattern != got[0] || parseHostPattern(v).String() != got[0]) {
			t.Fatalf("Lookup(%q) = %q, %q, %v; Matches %q", host, v, pattern, ok, got)
		}
	})
}

func BenchmarkMapMatches(b *testing.B) {
	var m Map[int]
	for i := range 1000 {
		m.Set(fmt.Sprintf("*.t%d.example.com", i), i)
	}
	m.Set("*.example.com", -1)
	m.Set("*", -2)
	b.ReportAllocs()
	for b.Loop() {
		n := 0
		for range m.Matches("a.b.t7.example.com") {
			n++
		}
		if n != 3 {
			b.Fatal(n)
		}
	}
}

func TestMapLookupFunc(t *testing.T) {
	var m Map[[]string] // the paths each pattern serves
	m.Set("www.example.com", []string{"/api"})
	m.Set("*.example.com", []string{"/", "/static"})
	serves := func(path string) func(string, []string) bool {
		return func(_ string, paths []string) bool { return slices.Contains(paths, path) }
	}
	if _, pattern, ok := m.LookupFunc("www.example.com", serves("/api")); !ok || pattern != "www.example.com" {
		t.Fatalf("/api: %q, %v", pattern, ok)
	}
	if _, pattern, ok := m.LookupFunc("www.example.com", serves("/static")); !ok || pattern != "*.example.com" {
		t.Fatalf("/static falls back: %q, %v", pattern, ok)
	}
	if _, _, ok := m.LookupFunc("www.example.com", serves("/none")); ok {
		t.Fatal("nothing accepted")
	}
	if n := testing.AllocsPerRun(100, func() { m.LookupFunc("www.example.com", serves("/static")) }); n != 0 {
		t.Fatalf("%v allocations", n)
	}
}
