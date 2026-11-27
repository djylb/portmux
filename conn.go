package portmux

import (
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/tlshello"
	"github.com/djylb/timeshim"
)

// Conn is a connection with the bytes that were read while matching it placed
// back in front of its stream: routes and Peek return one.
//
// Reads first return those bytes and then continue with the client's stream.
// When a PROXY protocol header was parsed, RemoteAddr and LocalAddr report its
// addresses.
type Conn struct {
	conn          net.Conn
	pending       []byte
	readErr       error
	replayDone    chan struct{} // waiters for an outstanding WriteTo
	buf           *[]byte
	parsed                   // what matching found, set once it ended
	track         *connTrack // for WithCloseEvents, or nil
	proxy         *proxyproto.Header
	route         *Route
	mux           *Mux      // counts the connection while open, with ln
	ln            *listener // the listener it came from, or nil
	entry         string
	writingPrefix bool
	closed        bool
	stripe        uint8 // of the counters, and the shard of the pending set
	mu            sync.Mutex
	drained       atomic.Bool
	open          atomic.Bool // counted as open by its route, listener and Mux
}

// Unread returns a copy of the bytes that are still to be replayed: the bytes
// read while matching that Read has not returned yet. Right after Peek or
// Accept these are all the bytes the client sent first, for example a whole
// ClientHello for a parser of your own.
func (c *Conn) Unread() []byte {
	if c.drained.Load() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.pending)
}

// connTrack measures a delivered connection for its close event, which goes
// to observe, the observer of the connection's settings.
type connTrack struct {
	clock         timeshim.Clock
	start         time.Time
	event         Event
	startErr      error
	observe       func(Event)
	mu            sync.Mutex
	active        int
	read, written int64
	closing       bool
	duration      time.Duration
}

// begin and end keep a close event pending until I/O already in progress
// has reported its byte count. Only connections with close events use them.
func (t *connTrack) begin() { t.mu.Lock(); t.active++; t.mu.Unlock() }
func (c *Conn) end(read, written int64) {
	t := c.track
	t.mu.Lock()
	t.read += read
	t.written += written
	t.active--
	c.reportCloseLocked(t)
}

// reportCloseLocked releases t.mu and reports a close once the last
// outstanding operation has accounted for its bytes.
func (c *Conn) reportCloseLocked(t *connTrack) {
	if !t.closing || t.active != 0 {
		t.mu.Unlock()
		return
	}
	t.closing = false
	read, written, duration := t.read, t.written, t.duration
	t.mu.Unlock()
	ev := t.event
	ev.Closed, ev.Read, ev.Written, ev.Duration = true, read, written, duration
	c.mux.observeWith(t.observe, ev)
}

// accepted starts measurement at transfer to a handler or listener.
func (c *Conn) accepted() *Conn {
	if t := c.track; t != nil {
		t.start, t.startErr = clockNow(t.clock)
	}
	return c
}

// A measurement failure is reported with the close event. Ownership of a
// connection already handed to its server is independent of its telemetry.
func clockNow(clock timeshim.Clock) (now time.Time, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = NewPanicError(v)
		}
	}()
	return clock.Now(), nil
}

// Read reads the replayed bytes first, then from the client.
func (c *Conn) Read(p []byte) (n int, err error) {
	if c.track != nil {
		c.track.begin()
		defer func() { c.end(int64(n), 0) }()
	}
	return c.read(p)
}

func (c *Conn) lockReplay() {
	c.mu.Lock()
	for c.writingPrefix && !c.closed {
		if c.replayDone == nil {
			c.replayDone = make(chan struct{})
		}
		done := c.replayDone
		c.mu.Unlock()
		<-done
		c.mu.Lock()
	}
}

func (c *Conn) read(p []byte) (int, error) {
	if !c.drained.Load() {
		c.lockReplay()
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			if len(c.pending) == 0 {
				err := c.readErr
				c.readErr = nil
				c.releaseLocked()
				c.mu.Unlock()
				return n, err
			}
			c.mu.Unlock()
			return n, nil
		}
		err := c.readErr
		c.readErr = nil
		c.releaseLocked()
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
		c.mu.Unlock()
	}
	return c.conn.Read(p)
}

// dropEmpty returns the read buffer of a connection that has no bytes to
// replay, so that a client that sent nothing yet holds none.
func (c *Conn) dropEmpty() {
	c.mu.Lock()
	if !c.writingPrefix && len(c.pending) == 0 && c.readErr == nil {
		c.releaseLocked()
	}
	c.mu.Unlock()
}

// WriteTo writes the replayed bytes and then copies the rest of the stream to
// w, so io.Copy can still use the underlying connection's fast paths.
func (c *Conn) WriteTo(w io.Writer) (n int64, err error) {
	if c.track != nil {
		c.track.begin()
		defer func() { c.end(n, 0) }()
	}
	return c.writeTo(w)
}

func (c *Conn) writeTo(w io.Writer) (int64, error) {
	var written int64
	if !c.drained.Load() {
		c.lockReplay()
		pending, buf, readErr := c.pending, c.buf, c.readErr
		c.pending, c.buf, c.readErr = nil, nil, nil
		if len(pending) > 0 {
			c.writingPrefix = true
			c.mu.Unlock()
			n, err := c.writePrefix(w, pending, buf, readErr)
			written = int64(n)
			if err != nil {
				return written, err
			}
		} else {
			c.drained.Store(true)
			c.mu.Unlock()
			putBuffer(buf)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				readErr = nil
			}
			return written, readErr
		}
	}
	n, err := io.Copy(w, c.conn)
	return written + n, err
}

// writePrefix owns buf until the destination reports how much it accepted.
func (c *Conn) writePrefix(w io.Writer, pending []byte, buf *[]byte, readErr error) (n int, err error) {
	defer func() {
		c.mu.Lock()
		if !c.closed && (n < len(pending) || readErr != nil && err != nil) {
			c.pending, c.buf, c.readErr = pending[n:], buf, readErr
			buf = nil
		} else {
			c.drained.Store(true)
		}
		c.finishReplayLocked()
		c.mu.Unlock()
		putBuffer(buf)
	}()
	n, err = w.Write(pending)
	if n < 0 || n > len(pending) {
		n, err = 0, io.ErrShortWrite
	}
	if n < len(pending) && err == nil {
		err = io.ErrShortWrite
	}
	return
}

func (c *Conn) finishReplayLocked() {
	c.writingPrefix = false
	if c.replayDone != nil {
		close(c.replayDone)
		c.replayDone = nil
	}
}

// ReadFrom copies r to the connection, so io.Copy can still use the underlying
// connection's fast paths.
func (c *Conn) ReadFrom(r io.Reader) (n int64, err error) {
	if c.track != nil {
		c.track.begin()
		defer func() { c.end(0, n) }()
	}
	return io.Copy(c.conn, r)
}

// Write writes to the client.
func (c *Conn) Write(p []byte) (n int, err error) {
	if c.track != nil {
		c.track.begin()
		defer func() { c.end(0, int64(n)) }()
	}
	return c.conn.Write(p)
}

// Close closes the connection.
// The first Close ends the connection's count as open and, with
// WithCloseEvents, reports it to the observer.
func (c *Conn) Close() error {
	err := c.conn.Close()
	c.mu.Lock()
	c.closed = true
	c.finishReplayLocked()
	c.pending = nil
	c.readErr = nil
	c.releaseLocked()
	c.mu.Unlock()
	if c.closeOpen() {
		if t := c.track; t != nil {
			var duration time.Duration
			clockErr := t.startErr
			if clockErr == nil {
				var now time.Time
				now, clockErr = clockNow(t.clock)
				if clockErr == nil {
					duration = now.Sub(t.start)
				}
			}
			t.mu.Lock()
			t.event.Err = clockErr
			t.closing, t.duration = true, duration
			c.reportCloseLocked(t)
		}
	}
	return err
}

// closeOpen ends the connection's count as open, once, and reports whether
// this call did.
func (c *Conn) closeOpen() bool {
	if c.open.CompareAndSwap(true, false) {
		c.route.open.Add(-1)
		c.mux.count(c.ln, c.stripe, func(n *counters) { n.open.Add(-1) })
		return true
	}
	return false
}

// CloseWrite shuts down the writing side when the underlying connection
// supports it, and returns errors.ErrUnsupported otherwise.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// CloseRead shuts down the reading side when the underlying connection
// supports it, and returns errors.ErrUnsupported otherwise.
func (c *Conn) CloseRead() error {
	if cr, ok := c.conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return errors.ErrUnsupported
}

// LocalAddr returns the PROXY header's destination address when one was
// parsed, and the connection's local address otherwise.
func (c *Conn) LocalAddr() net.Addr {
	if c.proxy != nil && c.proxy.Destination != nil {
		return c.proxy.Destination
	}
	return c.conn.LocalAddr()
}

// RemoteAddr returns the PROXY header's source address when one was parsed,
// and the connection's remote address otherwise.
func (c *Conn) RemoteAddr() net.Addr {
	if c.proxy != nil && c.proxy.Source != nil {
		return c.proxy.Source
	}
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines of the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline of the underlying connection. Reads
// of replayed bytes do not block and ignore it.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline of the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// NetConn returns the connection accepted from the underlying listener.
// Reading from it directly skips the replayed bytes.
func (c *Conn) NetConn() net.Conn {
	return c.conn
}

// ClientHello returns the TLS ClientHello parsed while matching, or nil when
// none was parsed. It is always set for routes that matched with TLS.
func (c *Conn) ClientHello() *tlshello.Hello {
	return c.hello
}

// HTTPRequest returns the HTTP/1.x request head parsed while matching, or
// nil when none was parsed. It is always set for routes that matched with
// HTTP1.
func (c *Conn) HTTPRequest() *httphead.RoutedRequest {
	return c.req
}

// HTTP2Request returns the first request of a cleartext HTTP/2 connection
// parsed while matching, or nil when none was parsed. It is always set for
// routes that matched with HTTP2.
func (c *Conn) HTTP2Request() *httphead.RoutedRequest {
	return c.req2
}

// RequestedName returns the host name the client asked for, as
// Input.RequestedName does: the name a matcher set with
// Input.SetRequestedName, or the SNI of the ClientHello, or the host of the
// HTTP request without its port, normalized, from what was parsed while
// matching, or "" without one.
func (c *Conn) RequestedName() string {
	return c.requestedName()
}

// Value returns the value that a matcher or resolver stored under key with
// Input.SetValue while the connection was matched, or nil, so that what a
// parser of your own found reaches the server of the route.
func (c *Conn) Value(key any) any {
	return c.value(key)
}

type eventAddresses struct{ remote, local, peer net.Addr }

func (in *Input) setPeer(c net.Conn) {
	in.peer = c.RemoteAddr()
	in.remote = in.peer
	in.local = c.LocalAddr()
}

func (in *Input) addresses() eventAddresses {
	return eventAddresses{remote: in.remote, local: in.local, peer: in.peer}
}

func (a eventAddresses) event(entry string, route *Route, p *parsed, err error) Event {
	return Event{Entry: entry, Route: route, Err: err, Remote: a.remote, Local: a.local, Peer: a.peer,
		Name: p.requestedName(), ClientHello: p.hello, HTTPRequest: p.req, HTTP2Request: p.req2, values: p.values}
}

// parsed is what matching found out about a connection: the protocol heads
// that were parsed, the values of Input.SetValue and the name of
// Input.SetRequestedName. Input.parsed fills it, and Conn and the events of
// the connection carry it.
type parsed struct {
	hello  *tlshello.Hello
	req    *httphead.RoutedRequest // HTTP/1.x
	req2   *httphead.RoutedRequest // h2c
	values valueList
	name   *hostmatch.Name // or nil
}

// value returns the value stored under key, or nil.
func (p *parsed) value(key any) any {
	return p.values.get(key)
}

// requestedName returns the normalized name of the first of the name, the
// hello and the requests that is set, or "".
func (p *parsed) requestedName() string {
	var n hostmatch.Name
	switch {
	case p.name != nil:
		n = *p.name
	case p.hello != nil:
		n = p.hello.Name()
	case p.req != nil:
		n = hostmatch.NormalizeHost(p.req.Host)
	case p.req2 != nil:
		n = hostmatch.NormalizeHost(p.req2.Host)
	}
	if !n.Valid() {
		return ""
	}
	return n.String()
}

// ProxyHeader returns the PROXY protocol header, or nil when none was parsed.
func (c *Conn) ProxyHeader() *proxyproto.Header {
	return c.proxy
}

// Entry returns the name of the entry the connection came through; see
// Mux.Entry.
func (c *Conn) Entry() string {
	return c.entry
}

// Route returns the route that matched the connection.
func (c *Conn) Route() *Route {
	return c.route
}

func (c *Conn) releaseLocked() {
	putBuffer(c.buf)
	c.buf = nil
	c.pending = nil
	c.drained.Store(true)
}

const sniffBufferSize = 4 << 10

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, sniffBufferSize)
		return &b
	},
}

func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func putBuffer(b *[]byte) {
	if b != nil {
		bufferPool.Put(b)
	}
}
