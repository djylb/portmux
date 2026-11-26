package portmux

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/portmux/ipmatch"
	"github.com/djylb/timeshim"
)

// clientNet returns the network of ip that per-client limits count it under,
// of the prefix lengths of WithClientPrefix.
func (o *options) clientNet(ip netip.Addr) netip.Prefix {
	ip = ipmatch.NormalizeAddr(ip)
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
	return int(maphash.Bytes(shardSeed, b[:]) % uint64(n)) //nolint:gosec // n is a positive shard count
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

// tryAcquire takes a slot unless limit, when positive, are taken.
func (l *slotLimit) tryAcquire(limit int) bool {
	return addBelow(&l.n, limit)
}

// addBelow adds one to n unless limit, when positive, is reached, and reports
// whether it did.
func addBelow(n *atomic.Int64, limit int) bool {
	for {
		v := n.Load()
		if limit > 0 && v >= int64(limit) {
			return false
		}
		if n.CompareAndSwap(v, v+1) {
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
// reached limit.
func (l *pendingLimit) acquire(client netip.Prefix, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count[client] >= limit {
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

const rateShards = 16

// evictSample is how many records of a shard eviction compares to find the
// oldest, so that it takes constant time.
const evictSample = 8

// records bounds the records of a table of clients, as
// WithClientRecords sets it.
type records struct {
	max  int // positive; or negative for no limit
	full FullPolicy
}

// isFull reports whether a table of n records has no room for another.
func (r records) isFull(n int64) bool { return r.max >= 0 && n >= int64(r.max) }

func (r records) reserve(n *atomic.Int64) bool { return r.max != 0 && addBelow(n, r.max) }

// sweepEvery is how many checks a shard of a rateLimit or a banList makes
// between sweeps of the records it no longer needs.
const sweepEvery = 1024

// sweepCount counts the checks of a shard toward its next sweep.
type sweepCount int

// due counts a check and reports whether the shard is to be swept now.
func (c *sweepCount) due() bool {
	if *c++; *c < sweepEvery {
		return false
	}
	*c = 0
	return true
}

// tokenBucket is a token bucket, whose rate and burst each call is given and
// whose times are those of the clock of its owner.
type tokenBucket struct {
	tokens float64
	last   time.Duration
}

// refilled returns the tokens of b at now.
func (b *tokenBucket) refilled(rate, burst float64, now time.Duration) float64 {
	return min(burst, b.tokens+(now-b.last).Seconds()*rate)
}

// take refills b at now and takes a token, reporting whether there was one.
func (b *tokenBucket) take(rate, burst float64, now time.Duration) bool {
	now = max(b.last, now)
	b.tokens, b.last = b.refilled(rate, burst, now), now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rateLimit is a token bucket per client for new connections.
type rateLimit struct {
	clock  timeshim.Clock
	epoch  time.Time
	rate   float64 // tokens per second
	burst  float64
	size   atomic.Int64 // tracked clients
	shards [rateShards]rateShard
}

type rateShard struct {
	mu     sync.Mutex
	checks sweepCount
	// fullSweep is when a full shard was last swept. A full shard is swept
	// at most once a second, so that many new clients cannot make every
	// check sweep.
	fullSweep time.Duration
	swept     bool
	bucket    map[netip.Prefix]tokenBucket
}

func newRateLimit(rate float64, burst int, clk timeshim.Clock, epoch time.Time) *rateLimit {
	// The maps of the shards are made on first use.
	return &rateLimit{rate: rate, burst: float64(max(burst, 1)), clock: clk, epoch: epoch}
}

// allow takes a token for a new connection of client and reports whether
// there was one.
func (l *rateLimit) allow(client netip.Prefix, rec records) bool {
	return l.allowAt(client, l.clock.Now().Sub(l.epoch), rec)
}

func (l *rateLimit) allowAt(client netip.Prefix, now time.Duration, rec records) bool {
	sh := l.shard(client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.checks.due() {
		l.sweep(sh, now)
	}
	tb, ok := sh.bucket[client]
	if !ok {
		if rec.isFull(l.size.Load()) && (!sh.swept || now-sh.fullSweep >= time.Second) {
			sh.fullSweep, sh.swept = now, true
			l.sweepAll(sh, now, rec)
		}
		switch {
		case rec.reserve(&l.size):
		case rec.full == FullFailClosed:
			return false
		case rec.full != FullEvictOldest || !l.evict(sh):
			return true // untracked
		}
		if sh.bucket == nil {
			sh.bucket = make(map[netip.Prefix]tokenBucket)
		}
		tb = tokenBucket{tokens: l.burst, last: now}
	}
	allowed := tb.take(l.rate, l.burst, now)
	sh.bucket[client] = tb
	return allowed
}

// sweep forgets clients whose bucket is full again, which behave as unknown
// clients.
func (l *rateLimit) sweep(sh *rateShard, now time.Duration) {
	for client, tb := range sh.bucket {
		if tb.refilled(l.rate, l.burst, now) >= l.burst {
			delete(sh.bucket, client)
			l.size.Add(-1)
		}
	}
}

func (l *rateLimit) shard(client netip.Prefix) *rateShard {
	return &l.shards[shardOf(client, rateShards)]
}

// sweepAll sweeps sh, whose lock is held, and while the table stays full
// the other shards that are free to lock: a full table may hold its stale
// records in other shards. TryLock keeps shards from waiting on each other.
func (l *rateLimit) sweepAll(sh *rateShard, now time.Duration, rec records) {
	l.sweep(sh, now)
	for i := range l.shards {
		o := &l.shards[i]
		if !rec.isFull(l.size.Load()) {
			return
		}
		if o == sh || !o.mu.TryLock() {
			continue
		}
		l.sweep(o, now)
		o.mu.Unlock()
	}
}

// evict forgets the client seen longest ago, of a sample from sh or else
// from the first other shard that is free to lock and has one, to give its
// room to a new client of sh, and reports whether there was one. TryLock
// keeps shards from waiting on each other.
func (l *rateLimit) evict(sh *rateShard) bool {
	start := 0
	for i := range l.shards {
		if &l.shards[i] == sh {
			start = i
		}
	}
	for i := range rateShards {
		o := &l.shards[(start+i)%rateShards]
		if o != sh && !o.mu.TryLock() {
			continue
		}
		found := o.evictOldest()
		if o != sh {
			o.mu.Unlock()
		}
		if found {
			return true
		}
	}
	return false
}

// evictOldest forgets the client of sh seen longest ago, of a sample.
func (sh *rateShard) evictOldest() bool {
	var victim netip.Prefix
	var oldest time.Duration
	found := false
	n := 0
	for client, tb := range sh.bucket {
		if !found || tb.last < oldest {
			victim, oldest, found = client, tb.last, true
		}
		if n++; n >= evictSample {
			break
		}
	}
	if found {
		delete(sh.bucket, victim)
	}
	return found
}
