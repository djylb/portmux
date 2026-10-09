package portmux

import (
	"sync"
)

// pendingShards is the number of independently locked parts of a pendingSet.
const pendingShards = 16

// pendingSet tracks every undelivered connection, so that Close can close
// them. Undecided connections from Serve are kept in accept order, so that the
// oldest one can be evicted when the pending limit is reached. A connection
// is kept in the shard of its counter stripe, so connections handled at once
// rarely share a lock.
type pendingSet struct {
	shards [pendingShards]pendingShard
}

type pendingShard struct {
	mu   sync.Mutex
	idle sniffList // undecided connections from Serve, oldest first
	busy sniffList // every other undelivered connection
}

// sniffList is an intrusive doubly linked list of sniffers.
type sniffList struct {
	head, tail *sniffer
}

func (l *sniffList) push(s *sniffer) {
	s.list, s.prev, s.next = l, l.tail, nil
	if l.tail != nil {
		l.tail.next = s
	} else {
		l.head = s
	}
	l.tail = s
}

// insert adds s in accept order. Goroutines may reach it out of order, but
// rarely by much.
func (l *sniffList) insert(s *sniffer) {
	at := l.tail
	for at != nil && at.seq > s.seq {
		at = at.prev
	}
	s.list, s.prev = l, at
	if at != nil {
		s.next, at.next = at.next, s
	} else {
		s.next, l.head = l.head, s
	}
	if s.next != nil {
		s.next.prev = s
	} else {
		l.tail = s
	}
}

func (l *sniffList) remove(s *sniffer) {
	if s.prev != nil {
		s.prev.next = s.next
	} else {
		l.head = s.next
	}
	if s.next != nil {
		s.next.prev = s.prev
	} else {
		l.tail = s.prev
	}
	s.list, s.prev, s.next = nil, nil, nil
}

func (p *pendingSet) shard(s *sniffer) *pendingShard {
	return &p.shards[s.conn.stripe%pendingShards]
}

func (p *pendingSet) add(s *sniffer, evictable bool) {
	sh := p.shard(s)
	sh.mu.Lock()
	if evictable {
		sh.idle.insert(s)
	} else {
		sh.busy.push(s)
	}
	sh.mu.Unlock()
}

// decided marks s as matched, which protects it from eviction.
func (p *pendingSet) decided(s *sniffer) {
	sh := p.shard(s)
	sh.mu.Lock()
	if s.list == &sh.idle {
		sh.idle.remove(s)
		sh.busy.push(s)
	}
	sh.mu.Unlock()
}

func (p *pendingSet) remove(s *sniffer) {
	sh := p.shard(s)
	sh.mu.Lock()
	if s.list != nil {
		s.list.remove(s)
	}
	sh.mu.Unlock()
}

// evictOldest closes the undecided connection from Serve that was accepted
// first. It reports whether there was one.
func (p *pendingSet) evictOldest() bool {
	oldest := -1
	var oldestSeq uint64
	for i := range p.shards {
		sh := &p.shards[i]
		sh.mu.Lock()
		if h := sh.idle.head; h != nil && (oldest < 0 || h.seq < oldestSeq) {
			oldest, oldestSeq = i, h.seq
		}
		sh.mu.Unlock()
	}
	if oldest < 0 {
		return false
	}
	sh := &p.shards[oldest]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	s := sh.idle.head
	if s == nil {
		return false
	}
	sh.idle.remove(s)
	sh.busy.push(s)
	// The lock keeps the sniffer from being released and reused while its
	// connection is closed.
	s.evicted.Store(true)
	_ = s.conn.conn.Close()
	return true
}

// closeAll closes the underlying connections without releasing their
// buffers, which their goroutines still use.
func (p *pendingSet) closeAll() {
	for i := range p.shards {
		sh := &p.shards[i]
		sh.mu.Lock()
		for _, l := range []*sniffList{&sh.idle, &sh.busy} {
			for s := l.head; s != nil; s = s.next {
				_ = s.conn.conn.Close()
			}
		}
		sh.mu.Unlock()
	}
}
