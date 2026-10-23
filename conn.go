package portmux

import (
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/tlshello"
)

// Conn is a connection with the bytes that were read while matching it placed
// back in front of its stream: routes and Peek return one.
//
// Reads first return those bytes and then continue with the client's stream.
// When a PROXY protocol header was parsed, RemoteAddr and LocalAddr report its
// addresses.
type Conn struct {
	conn    net.Conn
	pending []byte
	buf     *[]byte
	hello   *tlshello.Hello
	req     *httphead.Request // HTTP/1.x
	req2    *httphead.Request // h2c
	values  []inputValue      // of Input.SetValue
	proxy   *proxyproto.Header
	route   *Route
	mux     *Mux      // counts the connection while open, with ln
	ln      *listener // the listener it came from, or nil
	entry   string
	stripe  uint8 // of the counters, and the shard of the pending set
	mu      sync.Mutex
	drained atomic.Bool
	open    atomic.Bool // counted as open by its route, listener and Mux
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

// Read reads the replayed bytes first, then from the client.
func (c *Conn) Read(p []byte) (int, error) {
	if !c.drained.Load() {
		c.mu.Lock()
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			if len(c.pending) == 0 {
				c.releaseLocked()
			}
			c.mu.Unlock()
			return n, nil
		}
		c.releaseLocked() // nothing to replay
		c.mu.Unlock()
	}
	return c.conn.Read(p)
}

// dropEmpty returns the read buffer of a connection that has no bytes to
// replay, so that a client that sent nothing yet holds none.
func (c *Conn) dropEmpty() {
	c.mu.Lock()
	if len(c.pending) == 0 {
		c.releaseLocked()
	}
	c.mu.Unlock()
}

// WriteTo writes the replayed bytes and then copies the rest of the stream to
// w, so io.Copy can still use the underlying connection's fast paths.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	var written int64
	if !c.drained.Load() {
		c.mu.Lock()
		pending, buf := c.pending, c.buf
		c.pending, c.buf = nil, nil
		c.drained.Store(true)
		c.mu.Unlock()
		if len(pending) > 0 {
			n, err := w.Write(pending)
			written = int64(n)
			putBuffer(buf)
			if err != nil {
				return written, err
			}
		} else {
			putBuffer(buf)
		}
	}
	n, err := io.Copy(w, c.conn)
	return written + n, err
}

// ReadFrom copies r to the connection, so io.Copy can still use the underlying
// connection's fast paths.
func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(c.conn, r)
}

// Write writes to the client.
func (c *Conn) Write(p []byte) (int, error) {
	return c.conn.Write(p)
}

// Close closes the connection.
// The first Close ends the connection's count as open.
func (c *Conn) Close() error {
	err := c.conn.Close()
	c.mu.Lock()
	c.pending = nil
	c.releaseLocked()
	c.mu.Unlock()
	c.closeOpen()
	return err
}

// closeOpen ends the connection's count as open, once.
func (c *Conn) closeOpen() {
	if c.open.CompareAndSwap(true, false) {
		c.route.open.Add(-1)
		c.mux.count(c.ln, c.stripe, func(n *counters) { n.open.Add(-1) })
	}
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
func (c *Conn) HTTPRequest() *httphead.Request {
	return c.req
}

// HTTP2Request returns the first request of a cleartext HTTP/2 connection
// parsed while matching, or nil when none was parsed. It is always set for
// routes that matched with HTTP2.
func (c *Conn) HTTP2Request() *httphead.Request {
	return c.req2
}

// RequestedName returns the host name the client asked for, as
// Input.RequestedName does: the SNI of the ClientHello, or the host of the
// HTTP request without its port, normalized, from what was parsed while
// matching, or "" without one.
func (c *Conn) RequestedName() string {
	return requestedName(c.hello, c.req, c.req2)
}

// requestedName returns the normalized name of the first that is parsed, or
// "".
func requestedName(hello *tlshello.Hello, req, req2 *httphead.Request) string {
	var n hostmatch.Name
	switch {
	case hello != nil:
		n = hello.Name()
	case req != nil:
		n = req.Name()
	case req2 != nil:
		n = req2.Name()
	}
	if !n.Valid() {
		return ""
	}
	return n.String()
}

// Value returns the value that a matcher or resolver stored under key with
// Input.SetValue while the connection was matched, or nil, so that what a
// parser of your own found reaches the server of the route.
func (c *Conn) Value(key any) any {
	for _, v := range c.values {
		if v.key == key {
			return v.value
		}
	}
	return nil
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
