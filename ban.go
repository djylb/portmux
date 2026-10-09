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
		m.bans.set(key, m.bans.now(), d)
	}
}

// Unban lifts the ban of client and reports whether it was banned.
func (m *Mux) Unban(client netip.Addr) bool {
	key, ok := clientKey(net.TCPAddrFromAddrPort(netip.AddrPortFrom(client, 0)))
	return ok && m.bans.set(key, m.bans.now(), 0)
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
	// maxBanClients bounds the clients a banList tracks. When they do not
	// fit, failures of new clients are not counted.
	maxBanClients = 1 << 16
)

// banList counts the failed connections of each client and bans clients for
// a while, automatically or on request.
type banList struct {
	epoch  time.Time
	size   atomic.Int64 // tracked clients, so that an empty list costs nothing
	shards [banShards]banShard
}

type banShard struct {
	mu      sync.Mutex
	checks  int
	clients map[netip.Addr]banEntry
}

type banEntry struct {
	start    time.Duration // start of the failure window, since epoch
	until    time.Duration // end of the ban, since epoch; zero when not banned
	failures int
}

func newBanList() *banList {
	l := &banList{epoch: time.Now()}
	for i := range l.shards {
		l.shards[i].clients = make(map[netip.Addr]banEntry)
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
	e, ok := sh.clients[client]
	return ok && e.until > now
}

// fail counts a failed connection of client and bans it for d once failures
// connections failed within window.
func (l *banList) fail(client netip.Addr, now time.Duration, failures int, window, d time.Duration) {
	sh := l.shard(client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.checks++; sh.checks >= rateSweepEvery {
		sh.checks = 0
		l.sweep(sh, now, window)
	}
	e, ok := sh.clients[client]
	if !ok {
		if len(sh.clients) >= maxBanClients/banShards {
			return
		}
		l.size.Add(1)
	}
	if e.until > now {
		return // already banned
	}
	if now-e.start > window {
		e.start, e.failures = now, 0
	}
	if e.failures++; e.failures >= failures {
		e.until, e.failures = now+d, 0
	}
	sh.clients[client] = e
}

// set bans client until now+d, or lifts its ban for d <= 0. It reports
// whether the client was banned before.
func (l *banList) set(client netip.Addr, now, d time.Duration) bool {
	sh := l.shard(client)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.clients[client]
	was := ok && e.until > now
	switch {
	case d > 0:
		if !ok {
			l.size.Add(1)
		}
		sh.clients[client] = banEntry{start: now, until: now + d}
	case ok:
		delete(sh.clients, client)
		l.size.Add(-1)
	}
	return was
}

// sweep forgets clients that are not banned and whose window has passed.
func (l *banList) sweep(sh *banShard, now, window time.Duration) {
	for client, e := range sh.clients {
		if e.until <= now && now-e.start > window {
			delete(sh.clients, client)
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
		for client, e := range sh.clients {
			if e.until > now {
				bans = append(bans, Ban{Client: clientPrefix(client), Until: l.epoch.Add(e.until)})
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
