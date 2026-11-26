package hostmatch

import (
	"errors"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

func TestSnapshotImmutable(t *testing.T) {
	var s0 *Snapshot[int]
	if _, _, ok := s0.Lookup("a.example"); ok || s0.Len() != 0 {
		t.Fatal("nil Snapshot is not empty")
	}
	s1 := s0.With("*.example", 1)
	s2 := s1.With("a.example", 2).With(".b.example", 3).With("*", 4)
	s3 := s2.Without("a.example")
	for _, tc := range []struct {
		s    *Snapshot[int]
		host string
		want int
		ok   bool
	}{
		{s1, "a.example", 1, true},
		{s1, "x.y", 0, false},
		{s2, "a.example", 2, true},
		{s2, "b.example", 3, true},
		{s2, "x.y", 4, true},
		{s3, "a.example", 1, true},
	} {
		if v, _, ok := tc.s.Lookup(tc.host); v != tc.want || ok != tc.ok {
			t.Errorf("Lookup(%q) = %d, %v; want %d, %v", tc.host, v, ok, tc.want, tc.ok)
		}
	}
	if s1.Len() != 1 || s2.Len() != 4 || s3.Len() != 3 {
		t.Errorf("Len %d %d %d", s1.Len(), s2.Len(), s3.Len())
	}
}

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{"A.Example.": "a.example", "*.EXAMPLE": "*.example", ".b.example": ".b.example", "*": "*", "": ""} {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMapEdit checks that the changes of TryEdit are seen together.
func TestMapEdit(t *testing.T) {
	var m Map[int]
	m.Set("a.example", 1)
	before := m.Load()
	if err := m.TryEdit(func(b *MapBuilder[int]) {
		b.Set("b.example", 2)
		if v, ok := b.Get("b.example"); !ok || v != 2 {
			t.Error("builder Get")
		}
		if !b.Delete("a.example") {
			t.Error("Delete")
		}
	}); err != nil {
		t.Fatal(err)
	}
	if before.Len() != 1 || m.Len() != 1 {
		t.Fatalf("lengths %d %d", before.Len(), m.Len())
	}
	if _, ok := m.Get("b.example"); !ok {
		t.Fatal("b.example missing")
	}
}

// TestBuilderMatchesMap builds random pattern sets with a MapBuilder, Set
// and Delete, and compares their lookups.
func TestBuilderMatchesMap(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 5))
	patterns := []string{"a.example", "*.example", ".example", "*.b.example", ".b.example", "c.b.example", "*", "", "A.EXAMPLE."}
	hosts := []string{"a.example", "example", "x.example", "b.example", "c.b.example", "d.c.b.example", "other", ""}
	for range 200 {
		var m Map[int]
		var b MapBuilder[int]
		var snaps []*Snapshot[int]
		var mapSnaps []map[string]int
		for i := range 30 {
			p := patterns[rng.IntN(len(patterns))]
			if rng.IntN(3) == 0 {
				m.Delete(p)
				b.Delete(p)
			} else {
				m.Set(p, i)
				b.Set(p, i)
			}
			if rng.IntN(5) == 0 {
				snaps = append(snaps, b.Snapshot())
				mapSnaps = append(mapSnaps, maps.Collect(m.All()))
			}
		}
		s := b.Snapshot()
		if s.Len() != m.Len() {
			t.Fatalf("Len %d, Map %d", s.Len(), m.Len())
		}
		for _, h := range hosts {
			var got, viaMap []string
			for p := range s.Matches(h) {
				got = append(got, p)
			}
			for p := range m.Matches(h) {
				viaMap = append(viaMap, p)
			}
			want := reference(slices.Collect(maps.Keys(maps.Collect(s.All()))), h)
			if !equal(got, want) || !equal(viaMap, want) {
				t.Fatalf("%q: %v, Map %v, want %v", h, got, viaMap, want)
			}
		}
		// Snapshots taken on the way are unchanged by later edits.
		for i, sn := range snaps {
			if got := maps.Collect(sn.All()); !maps.Equal(got, mapSnaps[i]) {
				t.Fatalf("snapshot %d changed: %v, want %v", i, got, mapSnaps[i])
			}
		}
	}
}

// reference returns the canonical patterns that match host, most specific
// first, as Snapshot documents the order, by matching each with a Set.
func reference(patterns []string, host string) []string {
	rank := func(p string) (int, int) {
		switch {
		case p == "*":
			return 3, 0
		case strings.HasPrefix(p, "*."):
			return 2, -2 * len(p[1:])
		case strings.HasPrefix(p, ".") && Normalize(host).String() != p[1:]:
			return 2, -2*len(p) + 1
		case strings.HasPrefix(p, "."):
			return 1, 0
		}
		return 0, 0
	}
	var out []string
	for _, p := range patterns {
		if NewSet(p).Match(host) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		ka, la := rank(a)
		kb, lb := rank(b)
		if ka != kb {
			return ka - kb
		}
		return la - lb
	})
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBuilderUpdate(t *testing.T) {
	var b MapBuilder[int]
	add := func(n int, _ bool) int { return n + 1 }
	for _, p := range []string{"A.example", "a.example.", "*.example", "*.example"} {
		b.Update(p, add)
	}
	s := b.Snapshot()
	if v, p, _ := s.Lookup("a.example"); v != 2 || p != "a.example" {
		t.Errorf("a.example = %d %q", v, p)
	}
	if v, _ := s.Get("*.example"); v != 2 {
		t.Errorf("*.example = %d", v)
	}
}

func TestTryEditConflict(t *testing.T) {
	var m Map[int]
	entered, release, done := make(chan struct{}, 2), make(chan struct{}), make(chan error, 2)
	for _, key := range []string{"alpha", "beta"} {
		go func() {
			done <- m.TryEdit(func(b *MapBuilder[int]) {
				entered <- struct{}{}
				<-release
				b.Set(key, 1)
				b.Set(key+"2", 2)
			})
		}()
	}
	<-entered
	<-entered
	close(release)
	if first, second := <-done, <-done; (first == nil) == (second == nil) || !errors.Is(errors.Join(first, second), ErrEditConflict) || m.Len() != 2 || len(entered) != 0 {
		t.Fatal(first, second, m.Len())
	}
	for _, key := range []string{"alpha", "beta"} {
		_, a := m.Get(key)
		_, b := m.Get(key + "2")
		if a != b {
			t.Fatal(key)
		}
	}
}

func TestUpdateAcrossSnapshot(t *testing.T) {
	for _, existing := range []bool{false, true} {
		var b MapBuilder[int]
		if existing {
			b.Set("key", 1)
		}
		var before *Snapshot[int]
		b.Update("key", func(old int, ok bool) int {
			before = b.Snapshot()
			b.Delete("key")
			b.Set("other", 3)
			if ok != existing {
				t.Fatal(ok, existing)
			}
			return old + 2
		})
		if value, ok := before.Get("key"); ok != existing || existing && value != 1 {
			t.Fatal(value, ok)
		}
		next := b.Snapshot()
		if value, ok := next.Get("key"); !ok || value != before.Len()+2 || next.Len() != 2 {
			t.Fatal(value, next.Len())
		}
	}
}

func TestTryEditPanic(t *testing.T) {
	var m Map[int]
	m.Set("key", 1)
	before := m.Load()
	err := m.TryEdit(func(b *MapBuilder[int]) { b.Delete("key"); panic("edit") })
	if e, ok := errors.AsType[*PanicError](err); !ok || e.Value != "edit" || len(e.Stack) == 0 || m.Load() != before {
		t.Fatal(err)
	}
}
