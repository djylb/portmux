package portmux

import (
	"errors"
	"testing"
	"time"
)

// TestSetOptionsWhileServing changes limits and timeouts of a running Mux.
func TestSetOptionsWhileServing(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithMaxPending(1), WithDispatchTimeout(0))
	stuck := m.Match(Prefix("A")) // nobody accepts yet
	serve(t, m)

	_, _ = dial(t, m).Write([]byte("A"))
	waitPending(t, m.Mux, 1)
	// The slot is taken by a matched connection, so the next one waits
	// until the limit is raised.
	_, _ = dial(t, m).Write([]byte("A"))
	time.Sleep(50 * time.Millisecond)
	if st := m.Stats(); st.Accepted != 1 {
		t.Fatalf("second connection taken at the limit: %+v", st)
	}
	m.SetOptions(WithMaxPending(2))
	waitPending(t, m.Mux, 2)
	accept(t, stuck)
	accept(t, stuck)

	// A shorter sniff timeout applies to the next connections.
	m.SetOptions(WithSniffTimeout(50 * time.Millisecond))
	c := dial(t, m)
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrSniffTimeout) {
		t.Fatalf("reported %v", err)
	}

	// Rate and per-client limits can be switched on and off.
	m.SetOptions(WithRateLimitPerIP(0.001, 1))
	_, _ = dial(t, m).Write([]byte("A"))
	accept(t, stuck)
	c = dial(t, m)
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("reported %v", err)
	}
	m.SetOptions(WithRateLimitPerIP(0, 0), WithMaxPendingPerIP(1))
	_, _ = dial(t, m).Write([]byte("A"))
	waitPending(t, m.Mux, 1)
	c = dial(t, m)
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("reported %v", err)
	}
	accept(t, stuck)
	m.SetOptions(WithMaxPendingPerIP(0))
	_, _ = dial(t, m).Write([]byte("A"))
	_, _ = dial(t, m).Write([]byte("A"))
	accept(t, stuck)
	accept(t, stuck)
}
