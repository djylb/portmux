package portmux

import "errors"

var (
	// ErrNoMatch is reported for a connection that no route accepted.
	ErrNoMatch = errors.New("portmux: no route matched")

	// ErrSniffTimeout is reported for a connection that did not send enough
	// bytes to be routed before the sniff timeout. The reported error also
	// wraps the read error.
	ErrSniffTimeout = errors.New("portmux: sniff timeout")

	// ErrDispatchTimeout is reported for a matched connection that its route
	// did not accept before the dispatch timeout.
	ErrDispatchTimeout = errors.New("portmux: dispatch timeout")

	// ErrPendingLimit is reported for a connection closed because its client
	// reached the WithMaxPendingPerIP limit.
	ErrPendingLimit = errors.New("portmux: too many pending connections from one client")

	// ErrRateLimited is reported for a connection closed because its client
	// or its listener took connections faster than WithRateLimitPerIP or
	// WithRateLimitPerListener allows.
	ErrRateLimited = errors.New("portmux: connection rate exceeded")

	// ErrBanned is reported for a connection closed because its client is
	// banned; see WithBanPerIP and Mux.Ban.
	ErrBanned = errors.New("portmux: client is banned")

	// ErrEvicted is reported for an undecided connection closed to make room
	// for a new one when the WithMaxPending limit was reached.
	ErrEvicted = errors.New("portmux: evicted to make room for new connections")

	// ErrRouteBusy is reported for a matched connection closed because its
	// route already had WithMaxQueuedPerRoute connections waiting for Accept
	// or MaxConns connections open.
	ErrRouteBusy = errors.New("portmux: route has too many connections waiting")

	// ErrRouteClosed is reported for a connection that a resolver sent to a
	// route that was closed or removed.
	ErrRouteClosed = errors.New("portmux: resolved to a closed route")

	// ErrRefused is reported for a connection closed by a reject route.
	ErrRefused = errors.New("portmux: refused by a reject route")

	// ErrDuplicateName is returned when a route name is already in use.
	ErrDuplicateName = errors.New("portmux: duplicate route name")
)
