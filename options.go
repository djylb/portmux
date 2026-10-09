package portmux

import (
	"net"
	"time"

	"github.com/djylb/netx/proxyproto"
)

// Defaults applied by New when the matching option is not given.
const (
	DefaultSniffTimeout      = 10 * time.Second
	DefaultDispatchTimeout   = 5 * time.Second
	DefaultMaxSniffBytes     = 16 << 10
	DefaultMaxPending        = 4096
	DefaultMaxQueuedPerRoute = 1024

	// MaxSniffBytes is the largest value WithMaxSniffBytes accepts.
	MaxSniffBytes = 16 << 20
)

type options struct {
	sniffTimeout    time.Duration
	dispatchTimeout time.Duration
	maxSniffBytes   int
	maxPending      int
	maxPendingPerIP int
	maxQueued       int
	rate            float64
	rateBurst       int
	listenerRate    float64
	listenerBurst   int
	banFailures     int
	banWindow       time.Duration
	banTime         time.Duration
	observer        func(Event)
	proxyPolicy     func(entry string, peer, local net.Addr) proxyproto.Policy
}

// Option configures New and Mux.SetOptions.
type Option func(*options)

// WithSniffTimeout bounds the time from accepting a connection until it is
// matched, including reading a PROXY protocol header. A connection that is
// still undecided when it expires is closed and reported with ErrSniffTimeout.
// A non-positive value disables the limit.
func WithSniffTimeout(d time.Duration) Option {
	return func(o *options) {
		o.sniffTimeout = d
	}
}

// WithDispatchTimeout bounds how long a matched connection waits for its
// route's Accept. The connection is closed and reported with
// ErrDispatchTimeout when it expires. A non-positive value waits until the
// route or the Mux is closed.
func WithDispatchTimeout(d time.Duration) Option {
	return func(o *options) {
		o.dispatchTimeout = d
	}
}

// WithMaxSniffBytes limits how many bytes are buffered while matching, not
// counting a PROXY protocol header. Once the limit is reached, matchers that
// still need more bytes are treated as not matching. A non-positive value
// selects DefaultMaxSniffBytes, and values above MaxSniffBytes are lowered to
// it.
func WithMaxSniffBytes(n int) Option {
	return func(o *options) {
		o.maxSniffBytes = n
	}
}

// WithMaxPending limits how many connections accepted by Serve may be
// undelivered at once, counting those being matched and those waiting for
// their route to accept them. At the limit, Serve closes the undecided
// connection that was accepted first, reported with ErrEvicted, to make room
// for the next one; legitimate clients are decided within a round trip, so
// the oldest undecided connections are the idle and slow ones. When every
// pending connection is already matched, Serve waits, which leaves further
// clients in the kernel's accept queue. A non-positive value removes the
// limit.
func WithMaxPending(n int) Option {
	return func(o *options) {
		o.maxPending = n
	}
}

// WithMaxPendingPerIP limits how many connections accepted by Serve from one
// client may be undelivered at once, so that a single client cannot use up
// the WithMaxPending budget with idle connections. Connections over the limit
// are closed at once and reported with ErrPendingLimit. A client is an IPv4
// address or an IPv6 /64 network of the peer of the TCP connection, not an
// address from a PROXY protocol header. A non-positive value, the default,
// removes the limit.
func WithMaxPendingPerIP(n int) Option {
	return func(o *options) {
		o.maxPendingPerIP = n
	}
}

// WithRateLimitPerIP limits how fast one client may open connections that
// Serve accepts: a token bucket per client refills perSecond tokens a second
// up to burst, and every connection takes one. Connections without a token
// are closed at once, before any byte is read, and reported with
// ErrRateLimited. Clients are counted as in WithMaxPendingPerIP. Up to 65536
// clients are tracked; beyond that, new clients pass unchecked. A
// non-positive rate, the default, disables the limit.
func WithRateLimitPerIP(perSecond float64, burst int) Option {
	return func(o *options) {
		o.rate, o.rateBurst = perSecond, burst
	}
}

// WithRateLimitPerListener limits how fast each listener served by Serve
// accepts connections in total, whatever their clients: a token bucket per
// listener refills perSecond tokens a second up to burst. Connections without
// a token are closed at once, before any byte is read, and reported with
// ErrRateLimited. It keeps a flood from many addresses, which per-client
// limits do not catch, from taking the CPU of every port. A non-positive
// rate, the default, disables the limit.
func WithRateLimitPerListener(perSecond float64, burst int) Option {
	return func(o *options) {
		o.listenerRate, o.listenerBurst = perSecond, burst
	}
}

// WithBanPerIP bans clients whose connections keep failing, as scanners'
// do: once failures connections from Serve of one client matched no route,
// timed out while sniffing, were refused by a reject route or sent an invalid
// PROXY header within window, the client's connections are refused for d,
// before any byte is read, and reported with ErrBanned. Connections that are
// closed without sending anything, as health checks are, do not count.
// Clients are counted as in WithMaxPendingPerIP; Mux.Ban and Mux.Bans manage
// bans directly. A non-positive failures, the default, disables automatic
// bans.
func WithBanPerIP(failures int, window, d time.Duration) Option {
	return func(o *options) {
		o.banFailures, o.banWindow, o.banTime = failures, window, d
	}
}

// WithMaxQueuedPerRoute limits how many matched connections may wait for one
// route's Accept, so that a route whose server stalls cannot take up the
// pending budget of the others. Connections over the limit are closed and
// reported with ErrRouteBusy. A non-positive value removes the limit.
func WithMaxQueuedPerRoute(n int) Option {
	return func(o *options) {
		o.maxQueued = n
	}
}

// WithObserver sets a function called with an Event for every connection
// that the Mux delivers or closes, from Serve or ServeConn, and for the
// temporary Accept errors that Serve retries, for access logs, metrics and
// error reports. Connections closed because the Mux was closed are not
// reported. The function must be safe for concurrent use. It runs
// synchronously, for limit errors in the accept loop, so it must be cheap
// under attack: prefer counting to logging every rejected connection.
func WithObserver(fn func(Event)) Option {
	return func(o *options) {
		o.observer = fn
	}
}

// WithProxyProtocol enables PROXY protocol v1 and v2 headers, parsed with
// github.com/djylb/netx/proxyproto. The policy is called for each connection
// with its entry, its peer and its local address, and decides whether a
// header is Required, Optional or to be ignored: per entry for the ports
// behind a load balancer, or per peer for the balancer's addresses. A parsed
// header is removed from the stream before matching, and its addresses
// replace those of the delivered Conn. Peek calls the policy with the empty
// entry. A missing required header is reported with proxyproto.ErrNoHeader,
// an invalid one with an error wrapping proxyproto.ErrMalformed.
//
// Use this option rather than a proxyproto.Listener in front of the Mux: the
// header is then read within the sniff timeout and the pending limits, and
// the accept loop never waits for it.
//
// Only trusted peers such as a load balancer should be allowed to send a
// header, since it lets the peer choose the reported client address.
func WithProxyProtocol(policy func(entry string, peer, local net.Addr) proxyproto.Policy) Option {
	return func(o *options) {
		o.proxyPolicy = policy
	}
}

func newOptions(opts []Option) options {
	cfg := options{
		sniffTimeout:    DefaultSniffTimeout,
		dispatchTimeout: DefaultDispatchTimeout,
		maxSniffBytes:   DefaultMaxSniffBytes,
		maxPending:      DefaultMaxPending,
		maxQueued:       DefaultMaxQueuedPerRoute,
	}
	cfg.apply(opts)
	return cfg
}

func (o *options) apply(opts []Option) {
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	if o.maxSniffBytes <= 0 {
		o.maxSniffBytes = DefaultMaxSniffBytes
	}
	o.maxSniffBytes = min(o.maxSniffBytes, MaxSniffBytes)
}
