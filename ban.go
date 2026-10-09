package portmux

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/proxyproto"
)

// banWorthy reports whether a connection failed in a way that counts toward
// WithBanPerIP.
func banWorthy(err error) bool {
	return errors.Is(err, ErrNoMatch) || errors.Is(err, ErrSniffTimeout) || errors.Is(err, ErrRefused) ||
		errors.Is(err, proxyproto.ErrMalformed) || errors.Is(err, proxyproto.ErrNoHeader)
}

// Ban refuses the connections that Serve accepts from client for d, before
// reading from them, with ErrBanned; an IPv6 client is banned with its /64
// network. A non-positive d lifts the ban. Connections passed to ServeConn
// are not checked.
func (m *Mux) Ban(client netip.Addr, d time.Duration) {
	if key, ok := clientKey(net.TCPAddrFromAddrPort(netip.AddrPortFrom(client, 0))); ok {
		m.bans.set(banKey{client: key}, m.bans.now(), d)
	}
}

// Unban lifts the ban of client and reports whether it was banned.
func (m *Mux) Unban(client netip.Addr) bool {
	key, ok := clientKey(net.TCPAddrFromAddrPort(netip.AddrPortFrom(client, 0)))
	return ok && m.bans.set(banKey{client: key}, m.bans.now(), 0)
}

// Ban is a banned client.
type Ban struct {
	// Client is the banned address, as a /32 for IPv4 and a /64 for IPv6.
	Client netip.Prefix
	// Until is when the ban ends.
	Until time.Time
}

// Bans returns the clients that are banned now, automatically or with Ban,
// in no particular order.
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
}

type banShard struct {
	mu      sync.Mutex
	checks  int
	clients map[banKey]banEntry
}

// banKey names a record of a client: the one with its ban and the failures
// counted for the Mux, or with own set, the failures counted for an entry
// with its own WithBanPerIP.
type banKey struct {
	client netip.Addr
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

func (l *banList) shard(client netip.Addr) *banShard {
	b := client.As16()
	return &l.shards[(b[15]^b[13]^b[11]^b[7])%banShards]
}

// banned reports whether client is banned at now.
func (l *banList) banned(client netip.Addr, now time.Duration) bool {
	if l.size.Load() == 0 {
		return false
	}
	sh := l.shard(client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.clients[banKey{client: client}]
	return ok && e.until > now
}

// fail counts a failed connection in the record key and bans its client for
// d once failures connections failed within window.
func (l *banList) fail(key banKey, now time.Duration, failures int, window, d time.Duration) {
	sh := l.shard(key.client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.checks++; sh.checks >= rateSweepEvery {
		sh.checks = 0
		l.sweep(sh, now)
	}
	ban := banKey{client: key.client}
	b, banned := sh.clients[ban]
	if banned && b.until > now {
		return // already banned
	}
	e, ok := sh.clients[key]
	if !ok && !l.track(sh) {
		return
	}
	if now-e.start > window {
		e.start, e.failures = now, 0
	}
	e.window = window
	if e.failures++; e.failures < failures {
		sh.clients[key] = e
		return
	}
	e.failures = 0
	sh.clients[key] = e
	if key != ban {
		if !banned && !l.track(sh) {
			return
		}
		e = b
	}
	e.until = now + d
	sh.clients[ban] = e
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
	sh := l.shard(key.client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.clients[key]
	was := ok && e.until > now
	switch {
	case d > 0:
		if !ok {
			l.size.Add(1)
		}
		sh.clients[key] = banEntry{start: now, until: now + d}
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

// list returns the banned clients with the end of their ban.
func (l *banList) list(now time.Duration) []Ban {
	var bans []Ban
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for key, e := range sh.clients {
			if e.until > now {
				bans = append(bans, Ban{Client: clientPrefix(key.client), Until: l.epoch.Add(e.until)})
			}
		}
		sh.mu.Unlock()
	}
	return bans
}

// clientPrefix returns the network a client key stands for.
func clientPrefix(client netip.Addr) netip.Prefix {
	if client.Is6() {
		return netip.PrefixFrom(client, 64)
	}
	return netip.PrefixFrom(client, 32)
}
