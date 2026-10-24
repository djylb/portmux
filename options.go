package portmux

import (
	"net"
	"net/netip"
	"time"

	"github.com/djylb/netx/proxyproto"
)

// Defaults applied by New when the matching option is not given.
const (
	DefaultSniffTimeout    = 10 * time.Second
	DefaultDispatchTimeout = 5 * time.Second
	DefaultMaxSniffBytes   = 16 << 10
	DefaultMaxPending      = 4096
	DefaultMaxQueued       = 1024

	// MaxSniffBytesLimit is the largest value WithMaxSniffBytes accepts.
	MaxSniffBytesLimit = 16 << 20
)

type options struct {
	sniffTimeout        time.Duration
	dispatchTimeout     time.Duration
	maxSniffBytes       int
	maxPending          int
	maxPendingPerClient int
	maxQueued           int
	rate                float64
	rateBurst           int
	listenerRate        float64
	listenerBurst       int
	banFailures         int
	banWindow           time.Duration
	banTime             time.Duration
	observer            func(Event)
	proxyPolicy         func(entry string, peer, local net.Addr) proxyproto.Policy
	clientBits4         int
	clientBits6         int
	closeEvents         bool
}

// Option configures a Mux; see New and Mux.SetOptions.
type Option interface {
	apply(o *options)
}

// EntryOption is an Option that can also be set for the connections of one
// entry alone; see Entry.SetOptions. The options that bound the Mux as a
// whole, WithMaxPending, WithObserver and WithProxyProtocol, are not entry
// options.
type EntryOption interface {
	Option
	setting() entrySetting
}

type optionFunc func(*options)

func (f optionFunc) apply(o *options) { f(o) }

// PeekOption is an Option that Peek takes as well: WithSniffTimeout,
// WithMaxSniffBytes and WithProxyProtocol.
type PeekOption interface {
	Option
	peekOption()
}

// SniffOption is an option of the sniffing that an entry and Peek can set
// too: WithSniffTimeout and WithMaxSniffBytes.
type SniffOption interface {
	EntryOption
	PeekOption
}

type peekFunc func(*options)

func (f peekFunc) apply(o *options) { f(o) }
func (peekFunc) peekOption()        {}

type sniffOption struct{ entryOption }

func (sniffOption) peekOption() {}

// entrySetting numbers the settings that entries can override.
type entrySetting uint8

const (
	settingSniffTimeout entrySetting = iota
	settingDispatchTimeout
	settingMaxSniffBytes
	settingMaxPendingPerClient
	settingRateLimitPerClient
	settingRateLimitPerListener
	settingBanPerClient
	settingMaxQueued
	numEntrySettings
)

type entryOption struct {
	s   entrySetting
	set func(*options)
}

func (e entryOption) apply(o *options)      { e.set(o) }
func (e entryOption) setting() entrySetting { return e.s }

// WithSniffTimeout bounds the time from taking a connection until it is
// matched, including reading a PROXY protocol header. Serve takes a
// connection once it has a pending slot, so the wait for one, see
// WithMaxPending, does not count. A connection that is
// still undecided when it expires is closed and reported with ErrSniffTimeout.
// A non-positive value disables the limit.
func WithSniffTimeout(d time.Duration) SniffOption {
	return sniffOption{entryOption{settingSniffTimeout, func(o *options) {
		o.sniffTimeout = d
	}}}
}

// WithDispatchTimeout bounds how long a matched connection waits for its
// route's Accept. The connection is closed and reported with
// ErrDispatchTimeout when it expires. A non-positive value waits until the
// route or the Mux is closed.
func WithDispatchTimeout(d time.Duration) EntryOption {
	return entryOption{settingDispatchTimeout, func(o *options) {
		o.dispatchTimeout = d
	}}
}

// WithMaxSniffBytes limits how many bytes are buffered while matching, not
// counting a PROXY protocol header. Once the limit is reached, matchers that
// still need more bytes are treated as not matching. A non-positive value
// selects DefaultMaxSniffBytes, and values above MaxSniffBytesLimit are
// lowered to it.
func WithMaxSniffBytes(n int) SniffOption {
	return sniffOption{entryOption{settingMaxSniffBytes, func(o *options) {
		o.maxSniffBytes = n
	}}}
}

// WithMaxPending limits how many connections accepted by Serve may be being
// matched at once. At the limit, Serve closes the undecided connection that
// was accepted first, reported with ErrEvicted, to make room for the next
// one; legitimate clients are decided within a round trip, so the oldest
// undecided connections are the idle and slow ones. Serve waits for the
// evicted connection to give its slot back, which leaves further clients in
// the kernel's accept queue meanwhile. A matched connection gives its slot
// back at once: those waiting for their route to accept them are bounded by
// WithMaxQueued and the dispatch timeout, so that a route that the same Mux
// serves, as when matching again inside TLS, never waits for slots that
// connections waiting for it hold. A connection matched again because its
// route was removed while it waited takes no slot again; the sniff timeout
// bounds it. A non-positive value removes the limit.
func WithMaxPending(n int) Option {
	return optionFunc(func(o *options) {
		o.maxPending = n
	})
}

// WithClientPrefix sets the networks that the per-client rules,
// WithMaxPendingPerClient, WithRateLimitPerClient and WithBanPerClient, and
// Mux.Ban count a client as: the IPv4 /v4 and the IPv6 /v6 network of its address. The
// defaults, 32 and 64, take an IPv4 address and the /64 network that one IPv6
// client usually holds; a shorter IPv6 prefix such as 56 groups clients whose
// provider hands out larger networks. Values out of range, below 1 or above
// 32 and 128, select the defaults. A change applies to new connections and
// bans; bans already set keep the networks they were set for, and still
// refuse their clients, while failures toward bans and the tokens of
// WithRateLimitPerClient start over for the new networks.
func WithClientPrefix(v4, v6 int) Option {
	return optionFunc(func(o *options) {
		o.clientBits4, o.clientBits6 = v4, v6
	})
}

// WithMaxPendingPerClient limits how many connections accepted by Serve from
// one client may be being matched at once, so that a single client cannot use
// up the WithMaxPending budget with idle connections; as there, a matched
// connection no longer counts. Connections over the limit
// are closed at once and reported with ErrPendingLimit. A client is the
// network, as WithClientPrefix sets it, of the peer of the connection or,
// for a peer that WithProxyProtocol lets send a header, of the source in its
// header. For such a peer the per-client rules apply once the header is read,
// with the peer itself as the client when it sends none where one is
// optional. The peer's own failures, such as a missing or broken header, and
// those of its connections without one, do not count toward banning anyone,
// so that a misconfigured load balancer is not banned with every client
// behind it; Mux.Ban still bans it. Until the header is read, its connections are
// bounded by WithMaxPending and the sniff timeout only, so allow headers only
// from trusted peers. A non-positive value, the default, removes the limit.
func WithMaxPendingPerClient(n int) EntryOption {
	return entryOption{settingMaxPendingPerClient, func(o *options) {
		o.maxPendingPerClient = n
	}}
}

// WithRateLimitPerClient limits how fast one client may open connections that
// Serve accepts: a token bucket per client refills perSecond tokens a second
// up to burst, and every connection takes one. Connections without a token
// are closed at once, before any byte is read past a PROXY header, and
// reported with ErrRateLimited. Clients are counted as in
// WithMaxPendingPerClient. Up to 65536 clients are tracked; beyond that, new
// clients pass unchecked. A non-positive rate, the default, disables the
// limit.
func WithRateLimitPerClient(perSecond float64, burst int) EntryOption {
	return entryOption{settingRateLimitPerClient, func(o *options) {
		o.rate, o.rateBurst = perSecond, burst
	}}
}

// WithRateLimitPerListener limits how fast each listener served by Serve
// accepts connections in total, whatever their clients: a token bucket per
// listener refills perSecond tokens a second up to burst. Connections without
// a token are closed at once, before any byte is read, and reported with
// ErrRateLimited. It keeps a flood from many addresses, which per-client
// limits do not catch, from taking the CPU of every port. A non-positive
// rate, the default, disables the limit.
func WithRateLimitPerListener(perSecond float64, burst int) EntryOption {
	return entryOption{settingRateLimitPerListener, func(o *options) {
		o.listenerRate, o.listenerBurst = perSecond, burst
	}}
}

// WithBanPerClient bans clients whose connections keep failing, as scanners'
// do: once failures connections from Serve of one client matched no route,
// timed out while sniffing, were refused by a reject route, or sent an invalid
// PROXY header or none where one is required within window, the client's
// connections are refused for d, before any byte is read past a PROXY
// header, and reported with ErrBanned; a banned peer that may send a header
// is refused before its header. Peers that WithProxyProtocol lets send a
// header are not banned automatically for their own failures; see
// WithMaxPendingPerClient. Connections that are closed without sending
// anything, as health checks are, do not count.
// Clients are counted as in WithMaxPendingPerClient; Mux.Ban, BanPrefix and
// Mux.Bans manage bans directly. A non-positive failures or d, the default,
// disables automatic bans.
func WithBanPerClient(failures int, window, d time.Duration) EntryOption {
	return entryOption{settingBanPerClient, func(o *options) {
		o.banFailures, o.banWindow, o.banTime = failures, window, d
	}}
}

// WithMaxQueued limits how many matched connections may wait for one
// route's Accept, which, with the dispatch timeout, bounds the connections
// and memory that a route whose server stalls holds: matched connections no
// longer count against WithMaxPending. Connections over the limit are closed
// and reported with ErrQueueFull. RouteConfig.MaxQueued overrides it for a
// route. A non-positive value removes the limit.
func WithMaxQueued(n int) EntryOption {
	return entryOption{settingMaxQueued, func(o *options) {
		o.maxQueued = n
	}}
}

// WithObserver sets a function called with an Event for every connection
// that the Mux delivers or closes, from Serve or ServeConn, and for the
// temporary Accept errors that Serve retries, for access logs, metrics and
// error reports. Connections closed because the Mux was closed are not
// reported. The function must be safe for concurrent use. It runs
// synchronously, for limit errors in the accept loop, so it must be cheap
// under attack: prefer counting to logging every rejected connection. It may
// call the methods of the Mux, but not wait for Shutdown, which waits for
// the Serve call that may be calling it: start Shutdown in a goroutine.
func WithObserver(fn func(Event)) Option {
	return optionFunc(func(o *options) {
		o.observer = fn
	})
}

// WithCloseEvents makes the observer of WithObserver receive one more Event
// for each delivered connection, when its server closes it with Conn.Close:
// with Closed set, how long it was open and how many bytes it carried, for
// access logs. The Mux then counts the bytes of delivered connections, which
// costs an atomic addition per read and write; without it, they are not
// counted. It applies to connections delivered after it is set.
func WithCloseEvents(on bool) Option {
	return optionFunc(func(o *options) {
		o.closeEvents = on
	})
}

// WithProxyProtocol enables PROXY protocol v1 and v2 headers, parsed with
// github.com/djylb/netx/proxyproto. The policy is called for each connection
// with its entry, its peer and its local address, and decides whether a
// header is Required, Optional or to be ignored: per entry for the ports
// behind a load balancer, or per peer for the balancer's addresses. A parsed
// header is removed from the stream before matching, and its addresses
// replace those of the delivered Conn. Peek calls the policy with the empty
// entry. A missing required header is reported with proxyproto.ErrNoHeader,
// an invalid one with an error wrapping proxyproto.ErrMalformed. An optional
// header is taken to be missing when the client sends nothing until a Silent
// check or the sniff timeout, so that Silent routes, and routes that decide
// without bytes such as those with Always, still take clients that wait for
// the server; the latter only at the sniff timeout, so give their entries a
// policy of Required or Ignore.
//
// Use this option rather than a proxyproto.Listener in front of the Mux: the
// header is then read within the sniff timeout and the pending limits, and
// the accept loop never waits for it. The policy, too, runs in the
// connection's goroutine once it has a pending slot, so a slow policy holds
// up only its connection and a panicking one closes only its connection.
// With a policy set, Serve applies the per-client rules there too, to the
// source of the header for a peer that sends one, and checks only bans of
// the peer when accepting; see WithMaxPendingPerClient.
//
// Only trusted peers such as a load balancer should be allowed to send a
// header, since it lets the peer choose the reported client address;
// TrustPeers gives a policy for a list of their addresses.
func WithProxyProtocol(policy func(entry string, peer, local net.Addr) proxyproto.Policy) PeekOption {
	return peekFunc(func(o *options) {
		o.proxyPolicy = policy
	})
}

// TrustPeers returns a policy for WithProxyProtocol under which the peers in
// prefixes, such as the addresses of a load balancer, must send a PROXY
// header on every entry, and other peers are served as they are, as
// proxyproto.TrustPrefixes reads the prefixes. A health check of the peer
// that sends bytes without a header then fails, though without banning the
// peer; let health checks send nothing, or write a policy of your own that
// makes headers optional, as it also may to tell entries apart.
func TrustPeers(prefixes ...netip.Prefix) func(entry string, peer, local net.Addr) proxyproto.Policy {
	trust := proxyproto.TrustPrefixes(prefixes...)
	return func(_ string, peer, _ net.Addr) proxyproto.Policy { return trust(peer) }
}

func newOptions(opts []Option) options {
	cfg := options{
		sniffTimeout:    DefaultSniffTimeout,
		dispatchTimeout: DefaultDispatchTimeout,
		maxSniffBytes:   DefaultMaxSniffBytes,
		maxPending:      DefaultMaxPending,
		maxQueued:       DefaultMaxQueued,
		clientBits4:     32,
		clientBits6:     64,
	}
	cfg.apply(opts)
	return cfg
}

func (o *options) apply(opts []Option) {
	for _, opt := range opts {
		if opt != nil {
			opt.apply(o)
		}
	}
	o.normalize()
}

func (o *options) normalize() {
	if o.maxSniffBytes <= 0 {
		o.maxSniffBytes = DefaultMaxSniffBytes
	}
	o.maxSniffBytes = min(o.maxSniffBytes, MaxSniffBytesLimit)
	if o.clientBits4 < 1 || o.clientBits4 > 32 {
		o.clientBits4 = 32
	}
	if o.clientBits6 < 1 || o.clientBits6 > 128 {
		o.clientBits6 = 64
	}
}

// Config reports the settings of a Mux, or those that apply to the
// connections of one entry, as the options set them; see Mux.Config and
// Entry.Config.
type Config struct {
	SniffTimeout        time.Duration
	DispatchTimeout     time.Duration
	MaxSniffBytes       int
	MaxPending          int
	MaxPendingPerClient int
	MaxQueued           int
	// RateLimitPerClient and RateBurstPerClient are the arguments of
	// WithRateLimitPerClient, and the next two those of WithRateLimitPerListener.
	RateLimitPerClient   float64
	RateBurstPerClient   int
	RateLimitPerListener float64
	RateBurstPerListener int
	// BanFailures, BanWindow and BanDuration are the arguments of
	// WithBanPerClient.
	BanFailures int
	BanWindow   time.Duration
	BanDuration time.Duration
	// ClientPrefix4 and ClientPrefix6 are the arguments of WithClientPrefix.
	ClientPrefix4 int
	ClientPrefix6 int
	// Observer and ProxyProtocol report whether WithObserver and
	// WithProxyProtocol set a function.
	Observer      bool
	ProxyProtocol bool
	// CloseEvents is the argument of WithCloseEvents.
	CloseEvents bool
}

// EntryOptions returns the options that set the settings of c that an entry
// can have, for Entry.SetOptions, so that settings read with Config, stored
// or changed, can be set again. Every setting then becomes the entry's own,
// with the values of c: the entry no longer follows later changes of the
// Mux's options, and its rate limit and ban counts become its own, as
// Entry.SetOptions describes; pick the options to set for less.
func (c Config) EntryOptions() []EntryOption {
	return []EntryOption{
		WithSniffTimeout(c.SniffTimeout),
		WithDispatchTimeout(c.DispatchTimeout),
		WithMaxSniffBytes(c.MaxSniffBytes),
		WithMaxPendingPerClient(c.MaxPendingPerClient),
		WithRateLimitPerClient(c.RateLimitPerClient, c.RateBurstPerClient),
		WithRateLimitPerListener(c.RateLimitPerListener, c.RateBurstPerListener),
		WithBanPerClient(c.BanFailures, c.BanWindow, c.BanDuration),
		WithMaxQueued(c.MaxQueued),
	}
}

// Options returns the options that set the settings of c, for New and
// Mux.SetOptions: those of EntryOptions, WithMaxPending, WithClientPrefix
// and WithCloseEvents. The functions of WithObserver and WithProxyProtocol,
// which Config does not hold, are not among them, so SetOptions keeps them.
func (c Config) Options() []Option {
	var opts []Option
	for _, o := range c.EntryOptions() {
		opts = append(opts, o)
	}
	return append(opts, WithMaxPending(c.MaxPending), WithClientPrefix(c.ClientPrefix4, c.ClientPrefix6), WithCloseEvents(c.CloseEvents))
}

func (o *options) config() Config {
	return Config{
		SniffTimeout:         o.sniffTimeout,
		DispatchTimeout:      o.dispatchTimeout,
		MaxSniffBytes:        o.maxSniffBytes,
		MaxPending:           o.maxPending,
		MaxPendingPerClient:  o.maxPendingPerClient,
		MaxQueued:            o.maxQueued,
		RateLimitPerClient:   o.rate,
		RateBurstPerClient:   o.rateBurst,
		RateLimitPerListener: o.listenerRate,
		RateBurstPerListener: o.listenerBurst,
		BanFailures:          o.banFailures,
		BanWindow:            o.banWindow,
		BanDuration:          o.banTime,
		Observer:             o.observer != nil,
		ProxyProtocol:        o.proxyPolicy != nil,
		ClientPrefix4:        o.clientBits4,
		ClientPrefix6:        o.clientBits6,
		CloseEvents:          o.closeEvents,
	}
}
