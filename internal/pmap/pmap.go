// Package pmap is a persistent map from strings to values: a hash array
// mapped trie whose updates copy only the path to the changed entry, so that
// versions share every part they have in common.
//
// A Map is an immutable value; its zero value is empty and costs nothing.
// Its size grows with its entries alone: a map of a few entries is one small
// node. A Builder changes a map in place, without copying the nodes it made
// itself, to load many entries at once.
package pmap

import (
	"hash/maphash"
	"iter"
	"math/bits"
	"slices"
)

const (
	bitsPerLevel = 5
	fanMask      = 1<<bitsPerLevel - 1
	// maxShift is the shift past which a hash has no bits left: entries of
	// equal hashes share a collision node there.
	maxShift = 64
)

var seed = maphash.MakeSeed()

func hash(key string) uint64 { return maphash.String(seed, key) }

// Hash returns the hash of key, for GetHashed.
func Hash(key string) uint64 { return hash(key) }

// Map is an immutable map from strings to V.
type Map[V any] struct {
	root *node[V]
	n    int
}

// node is a level of the trie. Below maxShift, bitmap has a bit for each
// slot, by its five bits of the hash; at maxShift it is zero and slots hold
// the leaves of one hash.
type node[V any] struct {
	owner  *owner // the Builder that may change it in place, or nil
	slots  []slot[V]
	bitmap uint32
}

// slot holds an entry, or a node when sub is not nil. Entries are held in
// place, to save an allocation and an indirection each.
type slot[V any] struct {
	sub  *node[V]
	key  string
	val  V
	hash uint64
}

// owner identifies a Builder. It is not empty, so that two owners never
// share an address.
type owner struct{ _ byte }

// Len returns the number of entries.
func (m Map[V]) Len() int { return m.n }

// Get returns the value of key.
func (m Map[V]) Get(key string) (V, bool) {
	if m.root == nil {
		var zero V
		return zero, false
	}
	if s := m.root.find(hash(key), key, 0); s != nil {
		return s.val, true
	}
	var zero V
	return zero, false
}

// GetHashed is Get with the Hash of key, to look one key up in several
// maps at the cost of one hash.
func (m Map[V]) GetHashed(h uint64, key string) (V, bool) {
	if m.root != nil {
		if s := m.root.find(h, key, 0); s != nil {
			return s.val, true
		}
	}
	var zero V
	return zero, false
}

// With returns m with key mapped to v.
func (m Map[V]) With(key string, v V) Map[V] {
	root, added := m.root.set(nil, slot[V]{key: key, val: v, hash: hash(key)}, 0)
	m.root = root
	if added {
		m.n++
	}
	return m
}

// Without returns m without key.
func (m Map[V]) Without(key string) Map[V] {
	root, removed := m.root.del(nil, hash(key), key, 0)
	if removed {
		m.root, m.n = root, m.n-1
	}
	return m
}

// All yields every entry, in no particular order.
func (m Map[V]) All() iter.Seq2[string, V] {
	return func(yield func(string, V) bool) { m.root.each(func(s *slot[V]) bool { return yield(s.key, s.val) }) }
}

// Diff calls fn for each key whose entry may differ between a and b: added,
// removed, or set again. It skips the nodes that the two share, so that its
// cost follows the changes when b was made from a; the entries of a node
// that differs are all reported, changed or not, so fn compares values
// where that matters.
func Diff[V any](a, b Map[V], fn func(key string, old V, hadOld bool, cur V, hasCur bool)) {
	diff(a.root, b.root, fn)
}

func (n *node[V]) find(h uint64, key string, shift uint) *slot[V] {
	for cur := n; cur != nil; {
		if shift >= maxShift {
			for i := range cur.slots {
				if cur.slots[i].key == key {
					return &cur.slots[i]
				}
			}
			return nil
		}
		bit := uint32(1) << (h >> shift & fanMask)
		if cur.bitmap&bit == 0 {
			return nil
		}
		s := &cur.slots[bits.OnesCount32(cur.bitmap&(bit-1))]
		if s.sub == nil {
			if s.hash == h && s.key == key {
				return s
			}
			return nil
		}
		cur, shift = s.sub, shift+bitsPerLevel
	}
	return nil
}

// editable returns n itself when o owns it, else a copy that o owns.
func (n *node[V]) editable(o *owner) *node[V] {
	if o != nil && n.owner == o {
		return n
	}
	c := &node[V]{owner: o, bitmap: n.bitmap, slots: make([]slot[V], len(n.slots), len(n.slots)+1)}
	copy(c.slots, n.slots)
	return c
}

func (n *node[V]) set(o *owner, e slot[V], shift uint) (*node[V], bool) {
	if n == nil {
		if shift >= maxShift {
			return &node[V]{owner: o, slots: []slot[V]{e}}, true
		}
		return &node[V]{owner: o, bitmap: 1 << (e.hash >> shift & fanMask), slots: []slot[V]{e}}, true
	}
	if shift >= maxShift {
		for i := range n.slots {
			if n.slots[i].key == e.key {
				c := n.editable(o)
				c.slots[i] = e
				return c, false
			}
		}
		c := n.editable(o)
		c.slots = append(c.slots, e)
		return c, true
	}
	bit := uint32(1) << (e.hash >> shift & fanMask)
	i := bits.OnesCount32(n.bitmap & (bit - 1))
	if n.bitmap&bit == 0 {
		c := n.editable(o)
		c.slots = append(c.slots, slot[V]{})
		copy(c.slots[i+1:], c.slots[i:])
		c.slots[i] = e
		c.bitmap |= bit
		return c, true
	}
	s := &n.slots[i]
	var sub *node[V]
	added := true
	switch {
	case s.sub != nil:
		sub, added = s.sub.set(o, e, shift+bitsPerLevel)
		if sub == s.sub {
			return n, added // changed in place
		}
	case s.hash == e.hash && s.key == e.key:
		c := n.editable(o)
		c.slots[i] = e
		return c, false
	default:
		// Two entries in one slot: push both a level down.
		sub, _ = (*node[V])(nil).set(o, *s, shift+bitsPerLevel)
		sub, _ = sub.set(o, e, shift+bitsPerLevel)
	}
	c := n.editable(o)
	c.slots[i] = slot[V]{sub: sub}
	return c, added
}

func (n *node[V]) del(o *owner, h uint64, key string, shift uint) (*node[V], bool) {
	if n == nil {
		return nil, false
	}
	if shift >= maxShift {
		for i := range n.slots {
			if n.slots[i].key == key {
				if len(n.slots) == 1 {
					return nil, true
				}
				c := n.editable(o)
				c.slots = slices.Delete(c.slots, i, i+1)
				return c, true
			}
		}
		return n, false
	}
	bit := uint32(1) << (h >> shift & fanMask)
	if n.bitmap&bit == 0 {
		return n, false
	}
	i := bits.OnesCount32(n.bitmap & (bit - 1))
	s := &n.slots[i]
	var rest slot[V]
	keep := false
	if s.sub != nil {
		sub, removed := s.sub.del(o, h, key, shift+bitsPerLevel)
		if !removed {
			return n, false
		}
		if sub == s.sub {
			return n, true // changed in place
		}
		switch {
		case sub != nil && len(sub.slots) == 1 && sub.slots[0].sub == nil:
			rest, keep = sub.slots[0], true // pull a lone entry up
		case sub != nil:
			rest, keep = slot[V]{sub: sub}, true
		}
	} else if s.hash != h || s.key != key {
		return n, false
	}
	if !keep {
		if len(n.slots) == 1 {
			return nil, true
		}
		c := n.editable(o)
		c.slots = slices.Delete(c.slots, i, i+1)
		c.bitmap &^= bit
		return c, true
	}
	c := n.editable(o)
	c.slots[i] = rest
	return c, true
}

// trim gives the nodes that o owns, which appends may have left with
// spare room, their exact size. Nodes that o owns are only below others
// it owns.
func (n *node[V]) trim(o *owner) {
	if n == nil || n.owner != o {
		return
	}
	if cap(n.slots)-len(n.slots) > 1 { // not the one spare slot of a copy
		n.slots = slices.Clip(slices.Clone(n.slots))
	}
	for i := range n.slots {
		n.slots[i].sub.trim(o)
	}
}

func (n *node[V]) each(yield func(*slot[V]) bool) bool {
	if n == nil {
		return true
	}
	for i := range n.slots {
		s := &n.slots[i]
		if s.sub == nil {
			if !yield(s) {
				return false
			}
		} else if !s.sub.each(yield) {
			return false
		}
	}
	return true
}

func diff[V any](a, b *node[V], fn func(string, V, bool, V, bool)) {
	if a == b {
		return
	}
	if a == nil || b == nil || a.bitmap == 0 || b.bitmap == 0 {
		diffEntries(collect(a, nil), collect(b, nil), fn)
		return
	}
	for both := a.bitmap | b.bitmap; both != 0; both &= both - 1 {
		bit := both & -both
		var sa, sb *slot[V]
		if a.bitmap&bit != 0 {
			sa = &a.slots[bits.OnesCount32(a.bitmap&(bit-1))]
		}
		if b.bitmap&bit != 0 {
			sb = &b.slots[bits.OnesCount32(b.bitmap&(bit-1))]
		}
		switch {
		case sa != nil && sb != nil && sa.sub != nil && sb.sub != nil:
			diff(sa.sub, sb.sub, fn)
		default:
			diffEntries(collect(nil, sa), collect(nil, sb), fn)
		}
	}
}

// collect returns the entries of n, or of s, which may be nil.
func collect[V any](n *node[V], s *slot[V]) []*slot[V] {
	switch {
	case s != nil && s.sub == nil:
		return []*slot[V]{s}
	case s != nil:
		n = s.sub
	}
	var out []*slot[V]
	n.each(func(e *slot[V]) bool {
		out = append(out, e)
		return true
	})
	return out
}

// diffEntries compares two lists of entries, of which one is short unless
// a and b share little.
func diffEntries[V any](a, b []*slot[V], fn func(string, V, bool, V, bool)) {
	var zero V
	var index map[string]*slot[V]
	if len(a) > 8 {
		index = make(map[string]*slot[V], len(a))
		for _, e := range a {
			index[e.key] = e
		}
	}
	matched := 0
	var seen map[string]bool
	if len(a) > 0 {
		seen = make(map[string]bool, min(len(a), len(b)))
	}
	for _, eb := range b {
		var ea *slot[V]
		if index != nil {
			ea = index[eb.key]
		} else {
			for _, x := range a {
				if x.key == eb.key {
					ea = x
					break
				}
			}
		}
		if ea == nil {
			fn(eb.key, zero, false, eb.val, true)
			continue
		}
		matched++
		seen[eb.key] = true
		fn(eb.key, ea.val, true, eb.val, true)
	}
	if matched == len(a) {
		return
	}
	for _, ea := range a {
		if !seen[ea.key] {
			fn(ea.key, ea.val, true, zero, false)
		}
	}
}

// Builder changes a Map in place. Its zero value starts from an empty map.
// Starting from an empty map, it gathers entries in a list and builds the
// trie once, with nodes of their exact size, when Map is called; from a map
// with entries, it changes the trie, copying each shared node it touches
// once. A Builder is not safe for concurrent use.
type Builder[V any] struct {
	owner *owner
	index map[string]int // of entries gathered in bulk in list, or nil
	list  []slot[V]
	m     Map[V]
	dead  int // entries of list deleted
}

// Builder returns a Builder that starts from m, which it does not change.
func (m Map[V]) Builder() *Builder[V] { return &Builder[V]{m: m} }

func (b *Builder[V]) own() *owner {
	if b.owner == nil {
		b.owner = &owner{}
	}
	return b.owner
}

// gathering reports whether b gathers entries in bulk, as it does from an
// empty map.
func (b *Builder[V]) gathering(hint int) bool {
	if b.index == nil && b.m.root == nil && b.owner == nil {
		b.index = make(map[string]int, hint)
		b.list = make([]slot[V], 0, hint)
	}
	return b.index != nil
}

// Grow hints that about n entries are to be set, so that a Builder that
// gathers in bulk makes room for them at once.
func (b *Builder[V]) Grow(n int) { b.gathering(max(n, 0)) }

// Len returns the number of entries.
func (b *Builder[V]) Len() int {
	if b.index != nil {
		return len(b.index)
	}
	return b.m.n
}

// Get returns the value of key.
func (b *Builder[V]) Get(key string) (V, bool) {
	if b.index != nil {
		if i, ok := b.index[key]; ok {
			return b.list[i].val, true
		}
		var zero V
		return zero, false
	}
	return b.m.Get(key)
}

// Set maps key to v.
func (b *Builder[V]) Set(key string, v V) {
	if b.gathering(0) {
		if i, ok := b.index[key]; ok {
			b.list[i].val = v
			return
		}
		b.index[key] = len(b.list)
		b.list = append(b.list, slot[V]{key: key, val: v}) // hashed by Map
		return
	}
	root, added := b.m.root.set(b.own(), slot[V]{key: key, val: v, hash: hash(key)}, 0)
	b.m.root = root
	if added {
		b.m.n++
	}
}

// Update sets key to the result of fn. The callback may snapshot or edit b.
func (b *Builder[V]) Update(key string, fn func(old V, ok bool) V) {
	old, ok := b.Get(key)
	b.Set(key, fn(old, ok))
}

// Delete removes key.
func (b *Builder[V]) Delete(key string) {
	if b.index != nil {
		if i, ok := b.index[key]; ok {
			delete(b.index, key)
			b.list[i].key = "" // dropped by Map, as index no longer names it
			b.dead++
		}
		return
	}
	root, removed := b.m.root.del(b.own(), hash(key), key, 0)
	if removed {
		b.m.root, b.m.n = root, b.m.n-1
	}
}

// Map returns the map built so far. Later changes of b do not change it.
func (b *Builder[V]) Map() Map[V] {
	if b.index != nil {
		es := b.list
		if b.dead > 0 {
			kept := es[:0]
			for i := range es {
				if j, ok := b.index[es[i].key]; ok && j == i {
					kept = append(kept, es[i])
				}
			}
			es = kept
		}
		for i := range es {
			es[i].hash = hash(es[i].key)
		}
		b.m = Map[V]{root: build(es, 0), n: len(es)}
		b.index, b.list, b.dead = nil, nil, 0
		return b.m
	}
	if b.owner != nil {
		b.m.root.trim(b.owner)
	}
	b.owner = nil // nodes made so far are now shared
	return b.m
}

// build returns the trie of es at shift, with nodes of their exact size.
// It sorts es in place by the bits of their hashes.
func build[V any](es []slot[V], shift uint) *node[V] {
	if len(es) == 0 {
		return nil
	}
	if shift >= maxShift {
		return &node[V]{slots: slices.Clone(es)}
	}
	chunk := func(e *slot[V]) uint64 { return e.hash >> shift & fanMask }
	var start, next [fanMask + 2]int
	for i := range es {
		start[chunk(&es[i])+1]++
	}
	n := &node[V]{}
	used := 0
	for i := range fanMask + 1 {
		if start[i+1] > 0 {
			n.bitmap |= 1 << i
			used++
		}
		start[i+1] += start[i]
	}
	// Put each entry in its bucket by swaps, as American flag sort does.
	next = start
	for c := range fanMask + 1 {
		for next[c] < start[c+1] {
			e := &es[next[c]]
			if d := chunk(e); d != uint64(c) {
				es[next[c]], es[next[d]] = es[next[d]], es[next[c]]
				next[d]++
			} else {
				next[c]++
			}
		}
	}
	n.slots = make([]slot[V], 0, used)
	for i := range fanMask + 1 {
		part := es[start[i]:start[i+1]]
		switch len(part) {
		case 0:
		case 1:
			n.slots = append(n.slots, part[0])
		default:
			n.slots = append(n.slots, slot[V]{sub: build[V](part, shift+bitsPerLevel)})
		}
	}
	return n
}
