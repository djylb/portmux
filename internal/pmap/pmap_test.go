package pmap

import (
	"maps"
	"math/rand/v2"
	"strconv"
	"testing"
)

func check(t *testing.T, m Map[int], want map[string]int) {
	t.Helper()
	if m.Len() != len(want) {
		t.Fatalf("Len = %d, want %d", m.Len(), len(want))
	}
	got := maps.Collect(m.All())
	if !maps.Equal(got, want) {
		t.Fatalf("All differs: %d entries, want %d", len(got), len(want))
	}
	for k, v := range want {
		if x, ok := m.Get(k); !ok || x != v {
			t.Fatalf("Get(%q) = %d, %v; want %d", k, x, ok, v)
		}
	}
}

// TestRandom compares maps, builders and diffs with Go maps.
func TestRandom(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for round := range 20 {
		keys := 1 + rng.IntN(2000)
		var m Map[int]
		want := map[string]int{}
		b := Map[int]{}.Builder()
		for i := range 3000 {
			k := strconv.Itoa(rng.IntN(keys))
			prev, prevWant := m, maps.Clone(want)
			if rng.IntN(3) == 0 {
				m = m.Without(k)
				b.Delete(k)
				delete(want, k)
			} else {
				m = m.With(k, i)
				b.Set(k, i)
				want[k] = i
			}
			if i%500 == 0 || round == 0 && i < 50 {
				check(t, m, want)
				check(t, prev, prevWant) // older versions stay unchanged
				Diff(prev, m, func(key string, old int, had bool, cur int, has bool) {
					if key != k && (!had || !has || old != cur) {
						t.Fatalf("Diff of a change of %q reports %q: %d %v, %d %v", k, key, old, had, cur, has)
					}
				})
				reported := 0
				Diff(prev, m, func(string, int, bool, int, bool) { reported++ })
				if reported > 64 {
					t.Fatalf("Diff of one change reports %d entries", reported)
				}
			}
		}
		check(t, m, want)
		built := b.Map()
		check(t, built, want)
		b.Set("after", -1) // must not change built
		check(t, built, want)
	}
}

// TestCollisions forces entries of one hash into collision nodes.
func TestCollisions(t *testing.T) {
	var n *node[int]
	keys := []string{"a", "b", "c"}
	for i, k := range keys {
		n, _ = n.set(nil, slot[int]{key: k, val: i, hash: 7}, 0)
	}
	for i, k := range keys {
		if s := n.find(7, k, 0); s == nil || s.val != i {
			t.Fatalf("find %q = %v", k, s)
		}
	}
	m2, _ := n.del(nil, 7, "b", 0)
	if m2.find(7, "b", 0) != nil || m2.find(7, "a", 0) == nil || n.find(7, "b", 0) == nil {
		t.Fatal("del in a collision node")
	}
	var gone []string
	diff(n, m2, func(k string, _ int, _ bool, _ int, has bool) {
		if !has {
			gone = append(gone, k)
		}
	})
	if len(gone) != 1 || gone[0] != "b" {
		t.Fatalf("diff = %v", gone)
	}
}

func TestDiffFull(t *testing.T) {
	var a, b Map[int]
	for i := range 100 {
		a = a.With(strconv.Itoa(i), i)
	}
	for i := 50; i < 150; i++ {
		b = b.With(strconv.Itoa(i), i)
	}
	var add, del, upd int
	Diff(a, b, func(_ string, _ int, had bool, _ int, has bool) {
		switch {
		case had && has:
			upd++
		case had:
			del++
		default:
			add++
		}
	})
	if add != 50 || del != 50 || upd != 50 {
		t.Fatalf("add %d del %d upd %d", add, del, upd)
	}
}
