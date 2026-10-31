package portmux

import (
	"errors"
	"testing"
	"time"

	"github.com/djylb/timeshim"
)

// TestSetMaxPendingWhileServing raises the pending limit of a running Mux:
// at the old limit a new connection evicts the oldest undecided one, at the
// new one it is taken alongside.
func TestSetMaxPendingWhileServing(t *testing.T) {
	m := startMux(t, WithMaxPending(1))
	m.Listen(Prefix("A"))
	serve(t, m)

	dial(t, m) // undecided: sends nothing
	waitPending(t, m.Mux, 1)
	dial(t, m)
	waitUntil(t, "the oldest is evicted", func() bool { return m.Stats().Evicted == 1 })
	m.SetOptions(WithMaxPending(2))
	dial(t, m)
	waitPending(t, m.Mux, 2)
	time.Sleep(20 * time.Millisecond)
	if st := m.Stats(); st.Evicted != 1 || st.Pending != 2 {
		t.Fatalf("stats %+v", st)
	}
}

// TestSetOptionsWhileServing changes limits and timeouts of a running Mux.
func TestSetOptionsWhileServing(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithDispatchTimeout(0))
	stuck := m.Listen(Prefix("A")) // nobody accepts yet
	serve(t, m)

	// A shorter sniff timeout applies to the next connections.
	m.SetOptions(WithSniffTimeout(50 * time.Millisecond))
	c := dial(t, m)
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrSniffTimeout) {
		t.Fatalf("reported %v", err)
	}

	// Rate and per-client limits can be switched on and off.
	m.SetOptions(WithRateLimitPerClient(0.001, 1))
	_, _ = dial(t, m).Write([]byte("A"))
	accept(t, stuck)
	c = dial(t, m)
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("reported %v", err)
	}
	// A connection still being matched holds the client's pending count.
	m.SetOptions(WithRateLimitPerClient(0, 0), WithMaxPendingPerClient(1), WithSniffTimeout(time.Minute))
	undecided := dial(t, m)
	waitPending(t, m.Mux, 1)
	c = dial(t, m)
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("reported %v", err)
	}
	_, _ = undecided.Write([]byte("A"))
	accept(t, stuck)
	m.SetOptions(WithMaxPendingPerClient(0))
	_, _ = dial(t, m).Write([]byte("A"))
	_, _ = dial(t, m).Write([]byte("A"))
	accept(t, stuck)
	accept(t, stuck)
}

func TestSetOptionsRefusesClock(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	defer func() {
		if recover() == nil {
			t.Error("SetOptions took WithClock")
		}
	}()
	m.SetOptions(WithClock(timeshim.Real))
}
