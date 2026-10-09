package portmux

import (
	"net"
	"syscall"
)

// waitReadable waits, without a buffer, until c has bytes or an error to
// read, or its read deadline passes, so that idle clients hold no read
// buffer. On Windows, a raw read that is not done yet waits with a
// zero-byte receive, which completes at once when bytes are already there.
func waitReadable(c net.Conn) error {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	waited := false
	err = rc.Read(func(uintptr) bool {
		done := waited
		waited = true
		return done
	})
	if err != nil && !isTimeout(err) {
		return nil // leave other errors, such as a closed connection, to Read
	}
	return err
}
