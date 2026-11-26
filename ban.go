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
	"github.com/djylb/timeshim"
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

const banShards = 16

// banList counts the failed connections of each client and bans clients for
// a while, automatically or on request.
type banList struct {
	clock  timeshim.Clock
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
	// earliest bounds the next time a sweep can remove a record.
	earliest time.Duration
	keys     []banKey // dense index for bounded admission sweeps
	cursor   int
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
	index    int // in banShard.keys
}

func newBanList(clk timeshim.Clock) *banList {
	return &banList{clock: clk, epoch: clk.Now()} // maps are made on first use
}

func (l *banList) now() time.Duration { return l.clock.Now().Sub(l.epoch) }

func (l *banList) shard(client netip.Prefix) *banShard {
	return &l.shards[shardOf(client, banShards)]
}

// banned reports whether a network that holds ip is banned at now, or,
// with rec failing closed, whether the list is full and ip has no record:
// neither the shared one nor, with own set, the one of entry.
func (l *banList) banned(ip netip.Addr, now time.Duration, rec records, entry string, own bool) bool {
	if l.size.Load() == 0 {
		return false
	}
	known := false
	for key := range l.keys(ip) {
		ban, ok := l.bannedKey(key, now, entry, own)
		if ban {
			return true
		}
		known = known || ok
	}
	if known || rec.full != FullFailClosed {
		return false
	}
	for i := range l.shards {
		if !rec.isFull(l.size.Load()) {
			return false
		}
		sh := &l.shards[i]
		sh.mu.Lock()
		l.reclaim(sh, now)
		sh.mu.Unlock()
	}
	return rec.isFull(l.size.Load())
}

// bannedKey reports whether client is banned at now, and whether it has a
// record: the shared one, or with own set, the one of entry.
func (l *banList) bannedKey(client netip.Prefix, now time.Duration, entry string, own bool) (banned, ok bool) {
	sh := l.shard(client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	key := banKey{client: client}
	e, ok := l.live(sh, key, now)
	if ok && e.until > now {
		return true, true
	}
	if own {
		_, ok = sh.clients[banKey{client: client, entry: entry, own: true}]
	}
	return false, ok
}

// live removes an expired shared record under its shard lock, so its slot
// can be used immediately for a new entry-specific failure window.
func (l *banList) live(sh *banShard, key banKey, now time.Duration) (banEntry, bool) {
	e, ok := sh.clients[key]
	if ok && e.expired(now) {
		sh.remove(key)
		l.size.Add(-1)
		return banEntry{}, false
	}
	return e, ok
}

func (sh *banShard) put(key banKey, e banEntry) {
	expiry := max(e.until, banEnd(e.start, e.window))
	if len(sh.clients) == 0 || expiry < sh.earliest {
		sh.earliest = expiry
	}
	if prev, ok := sh.clients[key]; ok {
		e.index = prev.index
	} else {
		e.index = len(sh.keys)
		sh.keys = append(sh.keys, key)
	}
	sh.clients[key] = e
}

// remove swaps the last key into the freed index.
func (sh *banShard) remove(key banKey) {
	e, ok := sh.clients[key]
	if !ok {
		return
	}
	last := len(sh.keys) - 1
	if e.index != last {
		moved := sh.keys[last]
		m := sh.clients[moved]
		m.index = e.index
		sh.clients[moved] = m
		sh.keys[e.index] = moved
	}
	sh.keys[last] = banKey{}
	sh.keys = sh.keys[:last]
	delete(sh.clients, key)
}

// reclaim checks a bounded part of a full shard. The next admission
// continues at the cursor even when no visited entry was expired.
func (l *banList) reclaim(sh *banShard, now time.Duration) {
	if now < sh.earliest {
		return
	}
	for range min(evictSample, len(sh.keys)) {
		if sh.cursor >= len(sh.keys) {
			sh.cursor = 0
		}
		key := sh.keys[sh.cursor]
		if sh.clients[key].expired(now) {
			sh.remove(key)
			l.size.Add(-1)
			return
		}
		sh.cursor++
	}
}

func (e banEntry) expired(now time.Duration) bool { return e.until <= now && now-e.start >= e.window }

// fail counts a failed connection in the record key and bans its client for
// d once failures connections failed within window. It reports whether it
// banned the client.
func (l *banList) fail(key banKey, now time.Duration, failures int, window, d time.Duration, rec records) bool {
	l.noteLength(key.client)
	sh := l.shard(key.client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.checks.due() {
		l.sweep(sh, now)
	}
	ban := banKey{client: key.client}
	b, banned := l.live(sh, ban, now)
	if banned && b.until > now {
		return false // already banned
	}
	e, ok := sh.clients[key]
	if !ok && !l.track(sh, now, rec, ban) {
		return false
	}
	if !ok || e.failures == 0 || now-e.start >= window {
		e.start, e.failures = now, 0
	}
	e.window = window
	if e.failures++; e.failures < failures {
		sh.put(key, e)
		return false
	}
	e.failures = 0
	if key != ban {
		sh.remove(key)
		if banned {
			l.size.Add(-1)
		}
		e = b
	}
	if e.failures == 0 {
		e.window = 0
	}
	e.until = banEnd(now, d)
	sh.put(ban, e)
	return true
}

// banEnd returns now+d, or the largest time for a ban too long to add.
func banEnd(now, d time.Duration) time.Duration {
	if now > math.MaxInt64-d {
		return math.MaxInt64
	}
	return now + d
}

// track makes room for a new record in sh, by rec, and reports whether
// there was some. Evicting, it keeps keep and the records of bans.
func (l *banList) track(sh *banShard, now time.Duration, rec records, keep banKey) bool {
	if rec.reserve(&l.size) {
		if sh.clients == nil {
			sh.clients = make(map[banKey]banEntry)
		}
		return true
	}
	if rec.full != FullEvictOldest {
		return false
	}
	// The oldest of a sample from this shard, else from the first other
	// shard that is free to lock and has one: a full list may hold its
	// records in other shards. TryLock keeps shards from waiting on each
	// other.
	start := l.index(sh)
	for i := range banShards {
		o := &l.shards[(start+i)%banShards]
		if o != sh && !o.mu.TryLock() {
			continue
		}
		found := o.evictOldest(now, keep)
		if o != sh {
			o.mu.Unlock()
		}
		if found {
			if sh.clients == nil { // the room moves to sh
				sh.clients = make(map[banKey]banEntry)
			}
			return true
		}
	}
	return false
}

// index returns the index of sh in l.shards.
func (l *banList) index(sh *banShard) int {
	for i := range l.shards {
		if &l.shards[i] == sh {
			return i
		}
	}
	return 0
}

// evictOldest forgets the oldest record of a sample that is not a ban nor
// keep, and reports whether there was one.
func (sh *banShard) evictOldest(now time.Duration, keep banKey) bool {
	var victim banKey
	var oldest time.Duration
	found := false
	n := 0
	for key, e := range sh.clients {
		if e.until <= now && key != keep && (!found || e.start < oldest) {
			victim, oldest, found = key, e.start, true
		}
		if n++; n >= evictSample {
			break
		}
	}
	if found {
		sh.remove(victim) // its room goes to the new record
	}
	return found
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
		// Bans set by hand are kept whatever the limit of records.
		if !ok {
			l.size.Add(1)
		}
		if sh.clients == nil {
			sh.clients = make(map[banKey]banEntry)
		}
		sh.put(key, banEntry{start: now, until: banEnd(now, d)})
	case ok:
		sh.remove(key)
		l.size.Add(-1)
	}
	return was
}

// sweep forgets the records of clients that are not banned and whose window
// has passed.
func (l *banList) sweep(sh *banShard, now time.Duration) {
	if now < sh.earliest {
		return
	}
	sh.earliest = math.MaxInt64
	for key, e := range sh.clients {
		if e.expired(now) {
			sh.remove(key)
			l.size.Add(-1)
		} else {
			sh.earliest = min(sh.earliest, max(e.until, banEnd(e.start, e.window)))
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
