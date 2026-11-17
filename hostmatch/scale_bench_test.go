package hostmatch

import (
	"strconv"
	"testing"
)

// BenchmarkMapScale looks names up in, and sets patterns of, a Map of n
// exact names and n/10 wildcards.
func BenchmarkMapScale(b *testing.B) {
	for _, n := range []int{10, 100_000, 1_000_000} {
		var m Map[int]
		for i := range n {
			m.Set("h"+strconv.Itoa(i)+".example.com", i)
			if i%10 == 0 {
				m.Set("*.w"+strconv.Itoa(i)+".example.com", i)
			}
		}
		b.Run("Lookup/"+strconv.Itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, ok := m.Lookup("h1.example.com"); !ok {
					b.Fatal("no match")
				}
			}
		})
		b.Run("LookupWildcard/"+strconv.Itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, ok := m.Lookup("a.b.w0.example.com"); !ok {
					b.Fatal("no match")
				}
			}
		})
		b.Run("Set/"+strconv.Itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				m.Set("h1.example.com", i)
				i++
			}
		})
	}
}
