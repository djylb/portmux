package portmux

import (
	"errors"
	"fmt"
)

var (
	// ErrNoMatch is reported for a connection that no route accepted, and
	// returned by Peek when its matchers ruled the connection out.
	ErrNoMatch = errors.New("portmux: no match for the connection")

	// ErrSniffTimeout is reported for a connection that did not send enough
	// bytes to be routed before the sniff timeout. The reported error also
	// wraps the read error.
	ErrSniffTimeout = errors.New("portmux: sniff timeout")

	// ErrDispatchTimeout is reported for a matched connection that its route
	// did not accept before the dispatch timeout.
	ErrDispatchTimeout = errors.New("portmux: dispatch timeout")

	// ErrPendingLimit is reported for a connection closed because its client
	// reached the WithMaxPendingPerClient limit.
	ErrPendingLimit = errors.New("portmux: too many pending connections from one client")

	// ErrRateLimited is reported for a connection closed because its client
	// or its listener took connections faster than WithRateLimitPerClient or
	// WithRateLimitPerListener allows.
	ErrRateLimited = errors.New("portmux: connection rate exceeded")

	// ErrBanned is reported for a connection closed because its client is
	// banned; see WithBanPerClient and Mux.Ban.
	ErrBanned = errors.New("portmux: client is banned")

	// ErrEvicted is reported for an undecided connection closed to make room
	// for a new one when the WithMaxPending limit was reached.
	ErrEvicted = errors.New("portmux: evicted to make room for new connections")

	// ErrQueueFull is reported for a matched connection closed because its
	// route already had WithMaxQueued connections waiting for Accept,
	// which tells that its server does not keep up.
	ErrQueueFull = errors.New("portmux: route has too many connections waiting")

	// ErrConnLimit is reported for a matched connection closed because its
	// route already had RouteConfig.MaxConns connections open.
	ErrConnLimit = errors.New("portmux: route has too many open connections")

	// ErrRouteClosed is reported for a connection that a resolver sent to a
	// route that was closed or removed.
	ErrRouteClosed = errors.New("portmux: resolved to a closed route")

	// ErrRefused is reported for a connection closed by a reject route.
	ErrRefused = errors.New("portmux: refused by a reject route")

	// ErrEntryMismatch is reported for a connection that a resolver sent to
	// a route limited to other entries; see RouteConfig.Entries.
	ErrEntryMismatch = errors.New("portmux: resolved to a route of another entry")

	// ErrDuplicateName is returned when a route name is already in use.
	ErrDuplicateName = errors.New("portmux: duplicate route name")

	// ErrInvalidRoute is wrapped by the errors that Add, Batch and the
	// setters of a Route return for a configuration that is not valid, such
	// as a fallback route with matchers, or for a route of another Mux; and
	// by the error reported for a connection that a resolver sent to a
	// route of another Mux.
	ErrInvalidRoute = errors.New("portmux: invalid route")
)

// PanicError is reported for a connection whose matcher, resolver, PROXY
// protocol policy or route handler panicked: the Mux recovers, closes the
// connection and goes on serving the others.
type PanicError struct {
	// Value is the value passed to panic.
	Value any
	// Stack is the stack of the goroutine that panicked.
	Stack []byte
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("portmux: panic serving a connection: %v", e.Value)
}
