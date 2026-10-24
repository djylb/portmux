package portmux

import (
	"errors"
	"iter"
	"math"
	mathbits "math/bits"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/ipmatch"
)

// banWorthy reports whether a connection failed in a way that counts toward
// WithBanPerClient.
func banWorthy(err error) bool {
	return errors.Is(err, ErrNoMatch) || errors.Is(err, ErrSniffTimeout) || errors.Is(err, ErrRefused) ||
		errors.Is(err, proxyproto.ErrMalformed) || errors.Is(err, proxyproto.ErrNoHeader)
}

// Ban refuses the connections that Serve accepts from client for d, before
// reading from them, with ErrBanned; the client is banned with its network,
// of the prefix lengths of WithClientPrefix. A non-positive d lifts the ban. Connections passed to ServeConn
// are not checked.
func (m *Mux) Ban(client netip.Addr, d time.Duration) {
	if client.IsValid() {
		m.bans.set(banKey{client: m.options().clientNet(client)}, m.bans.now(), d)
	}
}

// BanPrefix bans the clients in network for d, as Ban does the network of
// one client; an IPv4-mapped IPv6 network is banned as IPv4. A non-positive
// d lifts the ban of network.
func (m *Mux) BanPrefix(network netip.Prefix, d time.Duration) {
	if network.IsValid() {
		m.bans.set(banKey{client: ipmatch.NormalizePrefix(network)}, m.bans.now(), d)
	}
}

// UnbanPrefix lifts the ban of network, as BanPrefix or Ban set it, and
// reports whether it was banned. Bans of other networks that hold some of
// its addresses stay; Unban lifts every ban of an address.
func (m *Mux) UnbanPrefix(network netip.Prefix) bool {
	return network.IsValid() && m.bans.set(banKey{client: ipmatch.NormalizePrefix(network)}, m.bans.now(), 0)
}

// Unban lifts the bans of the networks that hold client, of the prefix
// lengths of WithClientPrefix now or when they were set, and reports whether
// it was banned.
func (m *Mux) Unban(client netip.Addr) bool {
	if !client.IsValid() {
		return false
	}
	was := false
	now := m.bans.now()
	for key := range m.bans.keys(client) {
		if m.bans.set(banKey{client: key}, now, 0) {
			was = true
		}
	}
	return was
}

// Ban is a banned client.
type Ban struct {
	// Client is the banned network, of the prefix lengths of
	// WithClientPrefix when it was banned.
	Client netip.Prefix
	// Until is when the ban ends.
	Until time.Time
}

// Bans returns the clients that are banned now, automatically or with Ban or
// BanPrefix, in no particular order.
func (m *Mux) Bans() []Ban {
	return m.bans.list(m.bans.now())
}

const (
	banShards = 16
	// maxBanClients bounds the records a banList keeps. When they do not fit,
	// failures of new clients are not counted.
	maxBanClients = 1 << 16
)

// banList counts the failed connections of each client and bans clients for
// a while, automatically or on request.
type banList struct {
	epoch  time.Time
	size   atomic.Int64 // records, so that an empty list costs nothing
	shards [banShards]banShard
	// lengths are the prefix lengths of the records ever made, a bit for
	// each IPv4 and each IPv6 length, so that a client is looked up under
	// every length that WithClientPrefix gave, not only the current one.
	lengths [2][3]atomic.Uint64
}

// family returns the index of the family of ip in lengths.
func family(ip netip.Addr) int {
	if ip.Is4() {
		return 0
	}
	return 1
}

// noteLength records the length of key.
func (l *banList) noteLength(key netip.Prefix) {
	bits := key.Bits()
	w := &l.lengths[family(key.Addr())][bits/64]
	if bit := uint64(1) << (bits % 64); w.Load()&bit == 0 {
		w.Or(bit)
	}
}

// keys yields the networks of ip, of every length recorded for its family.
func (l *banList) keys(ip netip.Addr) iter.Seq[netip.Prefix] {
	ip = ipmatch.NormalizeAddr(ip)
	return func(yield func(netip.Prefix) bool) {
		ws := &l.lengths[family(ip)]
		for i := range ws {
			for w := ws[i].Load(); w != 0; w &= w - 1 {
				bits := i*64 + mathbits.TrailingZeros64(w)
				if bits > ip.BitLen() {
					return
				}
				if !yield(netip.PrefixFrom(ip, bits).Masked()) {
					return
				}
			}
		}
	}
}

type banShard struct {
	mu      sync.Mutex
	checks  sweepCount
	clients map[banKey]banEntry
}

// banKey names a record of a client: the one with its ban and the failures
// counted for the Mux, or with own set, the failures counted for an entry
// with its own WithBanPerClient.
type banKey struct {
	client netip.Prefix
	entry  string
	own    bool
}

type banEntry struct {
	start    time.Duration // start of the failure window, since epoch
	window   time.Duration // length of the failure window
	until    time.Duration // end of the ban, since epoch; zero when not banned
	failures int
}

func newBanList() *banList {
	l := &banList{epoch: time.Now()}
	for i := range l.shards {
		l.shards[i].clients = make(map[banKey]banEntry)
	}
	return l
}

func (l *banList) now() time.Duration { return time.Since(l.epoch) }

func (l *banList) shard(client netip.Prefix) *banShard {
	return &l.shards[shardOf(client, banShards)]
}

// banned reports whether a network that holds ip is banned at now.
func (l *banList) banned(ip netip.Addr, now time.Duration) bool {
	if l.size.Load() == 0 {
		return false
	}
	for key := range l.keys(ip) {
		if l.bannedKey(key, now) {
			return true
		}
	}
	return false
}

func (l *banList) bannedKey(client netip.Prefix, now time.Duration) bool {
	sh := l.shard(client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.clients[banKey{client: client}]
	return ok && e.until > now
}

// fail counts a failed connection in the record key and bans its client for
// d once failures connections failed within window. It reports whether it
// banned the client.
func (l *banList) fail(key banKey, now time.Duration, failures int, window, d time.Duration) bool {
	l.noteLength(key.client)
	sh := l.shard(key.client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.checks.due() {
		l.sweep(sh, now)
	}
	ban := banKey{client: key.client}
	b, banned := sh.clients[ban]
	if banned && b.until > now {
		return false // already banned
	}
	e, ok := sh.clients[key]
	if !ok && !l.track(sh) {
		return false
	}
	if now-e.start > window {
		e.start, e.failures = now, 0
	}
	e.window = window
	if e.failures++; e.failures < failures {
		sh.clients[key] = e
		return false
	}
	e.failures = 0
	sh.clients[key] = e
	if key != ban {
		if !banned && !l.track(sh) {
			return false
		}
		e = b
	}
	e.until = banEnd(now, d)
	sh.clients[ban] = e
	return true
}

// banEnd returns now+d, or the largest time for a ban too long to add.
func banEnd(now, d time.Duration) time.Duration {
	if d > math.MaxInt64-now {
		return math.MaxInt64
	}
	return now + d
}

// track makes room for a new record in sh and reports whether there was
// some.
func (l *banList) track(sh *banShard) bool {
	if len(sh.clients) >= maxBanClients/banShards {
		return false
	}
	l.size.Add(1)
	return true
}

// set bans the client of key until now+d, or lifts its ban for d <= 0. It
// reports whether the client was banned before.
func (l *banList) set(key banKey, now, d time.Duration) bool {
	if d > 0 {
		l.noteLength(key.client)
	}
	sh := l.shard(key.client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	// Bans set by hand are swept here too, so that they do not pile up when
	// no failures are counted.
	if sh.checks.due() {
		l.sweep(sh, now)
	}
	e, ok := sh.clients[key]
	was := ok && e.until > now
	switch {
	case d > 0:
		if !ok {
			l.size.Add(1)
		}
		sh.clients[key] = banEntry{start: now, until: banEnd(now, d)}
	case ok:
		delete(sh.clients, key)
		l.size.Add(-1)
	}
	return was
}

// sweep forgets the records of clients that are not banned and whose window
// has passed.
func (l *banList) sweep(sh *banShard, now time.Duration) {
	for key, e := range sh.clients {
		if e.until <= now && now-e.start > e.window {
			delete(sh.clients, key)
			l.size.Add(-1)
		}
	}
}

// list returns the banned clients with the end of their ban, and forgets the
// records that sweep would.
func (l *banList) list(now time.Duration) []Ban {
	var bans []Ban
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		l.sweep(sh, now)
		for key, e := range sh.clients {
			if e.until > now {
				bans = append(bans, Ban{Client: key.client, Until: l.epoch.Add(e.until)})
			}
		}
		sh.mu.Unlock()
	}
	return bans
}
