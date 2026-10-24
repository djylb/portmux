package portmux

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/portmux/ipmatch"
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
	return addBelow(&l.n, max)
}

// addBelow adds one to n unless max, when positive, is reached, and reports
// whether it did.
func addBelow(n *atomic.Int64, max int) bool {
	for {
		v := n.Load()
		if max > 0 && v >= int64(max) {
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
)

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
	b.tokens, b.last = b.refilled(rate, burst, now), now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rateLimit is a token bucket per client for new connections.
type rateLimit struct {
	rate   float64 // tokens per second
	burst  float64
	epoch  time.Time
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
	if sh.checks.due() {
		l.sweep(sh, now)
	}
	tb, ok := sh.bucket[client]
	if !ok {
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
		}
	}
}
