package portmux

import (
	"maps"
	"net"
	"net/netip"
	"slices"
)

// Entry is a named group of the listeners a Mux serves, such as the public
// HTTPS ports or the ports behind a load balancer. Routes can be limited to
// entries with RouteConfig.Entries, so that the listeners and the services
// behind them are configured apart: a service picks the entries it is offered
// on. Matchers and resolvers see the entry of each connection, whatever the
// addresses in a PROXY protocol header say, and an entry can have options of
// its own, such as a shorter sniff timeout or stricter limits.
//
// Entries need no setup: Mux.Entry returns a handle for any name, and the
// empty name is the entry of Mux.Serve and Mux.ServeConn.
type Entry struct {
	m    *Mux
	name string
}

// Entry returns the handle of the entry with the given name.
func (m *Mux) Entry(name string) *Entry {
	return &Entry{m: m, name: name}
}

// Entries returns, sorted, the names of the entries that routes are limited
// to, that have options of their own or whose listeners the Mux serves. A
// name passed to Mux.Entry that is none of them, such as a misspelt one, has
// nothing of its own: its connections take the routes and options of every
// entry, which a program can check for when it configures the entries.
func (m *Mux) Entries() []string {
	names := make(map[string]bool)
	for name := range m.table.Load().byEntry {
		names[name] = true
	}
	if entries := m.entries.Load(); entries != nil {
		for name := range *entries {
			names[name] = true
		}
	}
	m.mu.Lock()
	for _, l := range m.listeners {
		names[l.entry] = true
	}
	m.mu.Unlock()
	return slices.Sorted(maps.Keys(names))
}

// Name returns the entry's name.
func (e *Entry) Name() string { return e.name }

// Serve serves ln as a listener of the entry; see Mux.Serve.
func (e *Entry) Serve(ln net.Listener) error { return e.m.serve(e.name, ln) }

// ServeConn routes c as a connection of the entry; see Mux.ServeConn.
func (e *Entry) ServeConn(c net.Conn) error { return e.m.serveOne(e.name, c) }

// SetOptions sets options for the connections of the entry alone, on top of
// those of the Mux; options that are not given keep their values, and later
// changes to the Mux's other options still apply. They take effect as
// Mux.SetOptions does.
//
// An entry with its own WithRateLimitPerClient keeps buckets of its own, and one
// with its own WithBanPerClient counts the failures of its clients apart; other
// entries share those of the Mux. A ban refuses the client on every entry.
// The per-client pending counts and the connections queued for a route,
// which the entry's WithMaxPendingPerClient and WithMaxQueued limit, are
// those of all entries.
func (e *Entry) SetOptions(opts ...EntryOption) {
	m := e.m
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.entryConfig(e.name)
	var set [numEntrySettings]func(*options)
	if old != nil {
		set = old.set
	}
	for _, opt := range opts {
		if opt != nil {
			set[opt.setting()] = opt.apply
		}
	}
	m.setEntryConfigLocked(e.name, m.newEntryConfig(old, set))
}

// ResetOptions drops options set for the entry, whose settings then follow
// the options of the Mux again: the settings of the options given, whatever
// their values, as in ResetOptions(WithSniffTimeout(0)), or every setting
// without any.
func (e *Entry) ResetOptions(opts ...EntryOption) {
	m := e.m
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.entryConfig(e.name)
	if old == nil {
		return
	}
	set := old.set
	if len(opts) == 0 {
		set = [numEntrySettings]func(*options){}
	}
	for _, opt := range opts {
		if opt != nil {
			set[opt.setting()] = nil
		}
	}
	if !slices.ContainsFunc(set[:], func(f func(*options)) bool { return f != nil }) {
		m.setEntryConfigLocked(e.name, nil)
		return
	}
	m.setEntryConfigLocked(e.name, m.newEntryConfig(old, set))
}

// Config returns the settings that apply to the connections of the entry:
// those of the Mux with the entry's own on top.
func (e *Entry) Config() Config {
	o, _ := e.m.settings(e.name)
	return o.config()
}

// entryConfig holds the options set for an entry and their result. It is
// never modified: changes replace it.
type entryConfig struct {
	set     [numEntrySettings]func(*options) // the latest option of each setting
	opts    *options                         // the Mux's options with set applied
	rate    *rateLimit                       // the entry's own buckets, or nil
	ownRate bool                             // whether rate replaces the Mux's
	ownBan  bool                             // whether failures are counted apart
}

// settings returns the options and the buckets of WithRateLimitPerClient for
// the connections of an entry.
func (m *Mux) settings(entry string) (*options, *rateLimit) {
	if c := m.entryConfig(entry); c != nil {
		if c.ownRate {
			return c.opts, c.rate
		}
		return c.opts, m.rate.Load()
	}
	return m.opts.Load(), m.rate.Load()
}

// banKey returns the record that counts the failures of client on entry.
func (m *Mux) banKey(entry string, client netip.Prefix) banKey {
	if c := m.entryConfig(entry); c != nil && c.ownBan {
		return banKey{client: client, entry: entry, own: true}
	}
	return banKey{client: client}
}

func (m *Mux) entryConfig(entry string) *entryConfig {
	if entries := m.entries.Load(); entries != nil {
		return (*entries)[entry]
	}
	return nil
}

// newEntryConfig applies the options set for an entry to those of the Mux.
// The entry's own buckets are kept while its own rate is unchanged. It runs
// with m.mu held.
func (m *Mux) newEntryConfig(old *entryConfig, set [numEntrySettings]func(*options)) *entryConfig {
	base := m.opts.Load()
	o := *base
	for _, apply := range set {
		if apply != nil {
			apply(&o)
		}
	}
	o.normalize()
	c := &entryConfig{set: set, opts: &o, ownRate: set[settingRateLimitPerClient] != nil, ownBan: set[settingBanPerClient] != nil}
	switch {
	case !c.ownRate || o.rate <= 0:
	case old != nil && old.rate != nil && old.opts.rate == o.rate && old.opts.rateBurst == o.rateBurst:
		c.rate = old.rate
	default:
		c.rate = newRateLimit(o.rate, o.rateBurst)
	}
	return c
}

// setEntryConfigLocked replaces the configuration of an entry, or drops it
// for nil. It runs with m.mu held.
func (m *Mux) setEntryConfigLocked(entry string, c *entryConfig) {
	entries := make(map[string]*entryConfig)
	if cur := m.entries.Load(); cur != nil {
		maps.Copy(entries, *cur)
	}
	if c == nil {
		delete(entries, entry)
	} else {
		entries[entry] = c
	}
	m.entries.Store(&entries)
}

// rebuildEntriesLocked applies the options of every entry again after the
// options of the Mux changed. It runs with m.mu held.
func (m *Mux) rebuildEntriesLocked() {
	cur := m.entries.Load()
	if cur == nil || len(*cur) == 0 {
		return
	}
	entries := make(map[string]*entryConfig, len(*cur))
	for name, c := range *cur {
		entries[name] = m.newEntryConfig(c, c.set)
	}
	m.entries.Store(&entries)
}
