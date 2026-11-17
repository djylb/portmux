package httproute

import (
	"net/http/httptest"
	"runtime"
	"strconv"
	"testing"

	"github.com/djylb/portmux/hostmatch"
)

var scaleSizes = []int{10, 100_000, 1_000_000}

// scaleConfig has n routes, one per host, each proxying to its own upstream.
func scaleConfig(n int) Config {
	c := Config{Routes: make([]Route, n), Upstreams: make([]Upstream, n)}
	for i := range n {
		s := strconv.Itoa(i)
		c.Upstreams[i] = Upstream{Name: "u" + s, Dial: noDial}
		c.Routes[i] = Route{Name: "r" + s, Hosts: []string{"h" + s + ".example"}, Proxy: &Proxy{Upstream: "u" + s}}
	}
	return c
}

func BenchmarkScaleBuild(b *testing.B) {
	for _, n := range scaleSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			c := scaleConfig(n)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Build(c); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkScaleWith replaces the route and upstream of one host.
func BenchmarkScaleWith(b *testing.B) {
	for _, n := range scaleSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			t, err := Build(scaleConfig(n))
			if err != nil {
				b.Fatal(err)
			}
			ch := Changes{
				Upstreams: []Upstream{{Name: "u1", Dial: noDial, MaxKeys: 7}},
				Routes:    []Route{{Name: "r1", Hosts: []string{"h1.example"}, Path: "/v2", Proxy: &Proxy{Upstream: "u1"}}},
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := t.With(ch); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkScaleUpdate updates a Router with a Table that With changed in
// one upstream.
func BenchmarkScaleUpdate(b *testing.B) {
	for _, n := range scaleSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			t0, err := Build(scaleConfig(n))
			if err != nil {
				b.Fatal(err)
			}
			t1, err := t0.With(Changes{Upstreams: []Upstream{{Name: "u1", Dial: noDial, MaxKeys: 7}}})
			if err != nil {
				b.Fatal(err)
			}
			r := New(Options{})
			defer func() { _ = r.Close() }()
			if err := r.Update(t0); err != nil {
				b.Fatal(err)
			}
			tables := [2]*Table{t1, t0}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if err := r.Update(tables[i&1]); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}

// BenchmarkScaleMemory reports the heap a Table and a Router holding it
// take per route, each route with its own upstream.
func BenchmarkScaleMemory(b *testing.B) {
	for _, n := range scaleSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			c := scaleConfig(n)
			var table, router float64
			for b.Loop() {
				before := heap()
				t, err := Build(c)
				if err != nil {
					b.Fatal(err)
				}
				mid := heap()
				r := New(Options{})
				if err := r.Update(t); err != nil {
					b.Fatal(err)
				}
				after := heap()
				table, router = float64(mid-before)/float64(n), float64(after-mid)/float64(n)
				runtime.KeepAlive(t)
				_ = r.Close()
			}
			b.ReportMetric(table, "table-B/route")
			b.ReportMetric(router, "router-B/upstream")
		})
	}
}

func heap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// BenchmarkScaleMatch looks a request up in a Table of n hosts.
func BenchmarkScaleMatch(b *testing.B) {
	for _, n := range scaleSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			t, err := Build(scaleConfig(n))
			if err != nil {
				b.Fatal(err)
			}
			req := httptest.NewRequest("GET", "http://h1.example/a/b", nil)
			name := hostmatch.Normalize("h1.example")
			rs := &reqState{}
			b.ReportAllocs()
			for b.Loop() {
				if t.match(name, "/a/b", req, rs) == nil {
					b.Fatal("no route")
				}
			}
		})
	}
}

// BenchmarkPoolAcquire acquires a new key in a pool whose MaxKeys keys
// are all held, so that each acquire evicts one.
func BenchmarkPoolAcquire(b *testing.B) {
	for _, n := range []int{8, 1024, 65536} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			p := newPool(&upstream{Upstream: Upstream{Name: "u", Dial: noDial, MaxKeys: n}})
			for i := range n {
				p.acquire(strconv.Itoa(i))
			}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				p.release(p.acquire("k" + strconv.Itoa(i)))
				i++
			}
		})
	}
}
