package portmux

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// clientNet returns the network of ip that per-IP limits count it under,
// of the prefix lengths of WithClientPrefix.
func (m *Mux) clientNet(ip netip.Addr) netip.Prefix {
	o := m.opts.Load()
	ip = ip.Unmap().WithZone("")
	bits := o.clientBits4
	if ip.Is6() {
		bits = o.clientBits6
	}
	return netip.PrefixFrom(ip, bits).Masked()
}

// shardSeed keys shardOf, so that clients cannot choose addresses that share
// a shard.
var shardSeed = maphash.MakeSeed()

// shardOf spreads clients over n shards by all bytes of their address: the
// keys of IPv6 clients are networks, whose last bytes are all zero.
func shardOf(client netip.Prefix, n int) int {
	b := client.Addr().As16()
	return int(maphash.Bytes(shardSeed, b[:]) % uint64(n))
}

// slotLimit counts the undelivered connections from Serve for
// WithMaxPending. The limit is passed to each call, so it can change.
type slotLimit struct {
	n       atomic.Int64
	waiters atomic.Int32
	free    chan struct{} // signalled when a slot may have become free
}

func newSlotLimit() *slotLimit {
	return &slotLimit{free: make(chan struct{}, 1)}
}

// tryAcquire takes a slot unless max, when positive, are taken.
func (l *slotLimit) tryAcquire(max int) bool {
	for {
		n := l.n.Load()
		if max > 0 && n >= int64(max) {
			return false
		}
		if l.n.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (l *slotLimit) release() {
	l.n.Add(-1)
	if l.waiters.Load() > 0 {
		l.signal()
	}
}

func (l *slotLimit) signal() {
	select {
	case l.free <- struct{}{}:
	default:
	}
}

// pendingLimit counts the undelivered connections of each client.
type pendingLimit struct {
	mu    sync.Mutex
	count map[netip.Prefix]int
}

// acquire counts a connection of client. It reports false when the client
// reached max.
func (l *pendingLimit) acquire(client netip.Prefix, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count[client] >= max {
		return false
	}
	l.count[client]++
	return true
}

func (l *pendingLimit) release(client netip.Prefix) {
	l.mu.Lock()
	if n := l.count[client]; n > 1 {
		l.count[client] = n - 1
	} else {
		delete(l.count, client)
	}
	l.mu.Unlock()
}

const (
	rateShards = 16
	// maxRateClients bounds the clients a rateLimit tracks. When they do not
	// fit, new clients pass untracked rather than being refused.
	maxRateClients = 1 << 16
	// rateSweepEvery is how many checks a shard makes between removals of
	// clients whose bucket has refilled.
	rateSweepEvery = 1024
)

// rateLimit is a token bucket per client for new connections.
type rateLimit struct {
	rate   float64 // tokens per second
	burst  float64
	epoch  time.Time
	shards [rateShards]rateShard
}

type rateShard struct {
	mu     sync.Mutex
	checks int
	// fullSweep is when a full shard was last swept. A full shard is swept
	// at most once a second, so that many new clients cannot make every
	// check sweep.
	fullSweep time.Duration
	swept     bool
	bucket    map[netip.Prefix]tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Duration // since epoch
}

func newRateLimit(rate float64, burst int) *rateLimit {
	l := &rateLimit{rate: rate, burst: float64(max(burst, 1)), epoch: time.Now()}
	for i := range l.shards {
		l.shards[i].bucket = make(map[netip.Prefix]tokenBucket)
	}
	return l
}

// allow takes a token for a new connection of client and reports whether
// there was one.
func (l *rateLimit) allow(client netip.Prefix) bool {
	return l.allowAt(client, time.Since(l.epoch))
}

func (l *rateLimit) allowAt(client netip.Prefix, now time.Duration) bool {
	sh := &l.shards[shardOf(client, rateShards)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.checks++; sh.checks >= rateSweepEvery {
		sh.checks = 0
		l.sweep(sh, now)
	}
	tb, ok := sh.bucket[client]
	if ok {
		tb.tokens = l.refill(tb, now)
	} else {
		if len(sh.bucket) >= maxRateClients/rateShards {
			if sh.swept && now-sh.fullSweep < time.Second {
				return true
			}
			sh.fullSweep, sh.swept = now, true
			l.sweep(sh, now)
			if len(sh.bucket) >= maxRateClients/rateShards {
				return true
			}
		}
		tb.tokens = l.burst
	}
	tb.last = now
	if tb.tokens < 1 {
		sh.bucket[client] = tb
		return false
	}
	tb.tokens--
	sh.bucket[client] = tb
	return true
}

func (l *rateLimit) refill(tb tokenBucket, now time.Duration) float64 {
	return min(l.burst, tb.tokens+(now-tb.last).Seconds()*l.rate)
}

// sweep forgets clients whose bucket is full again, which behave as unknown
// clients.
func (l *rateLimit) sweep(sh *rateShard, now time.Duration) {
	for client, tb := range sh.bucket {
		if l.refill(tb, now) >= l.burst {
			delete(sh.bucket, client)
		}
	}
}
