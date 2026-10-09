//go:build linux || android || darwin || ios || freebsd || netbsd || openbsd

package portmux

import (
	"errors"
	"net"
	"syscall"
)

// waitReadable waits, without a buffer, until c has bytes or an error to
// read, or its read deadline passes, so that idle clients hold no read
// buffer. Each wakeup peeks at the socket, as Read would, so bytes that
// arrived before the wait are not missed. Connections without a socket
// return at once and are read directly.
func waitReadable(c net.Conn) error {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	var peek [1]byte
	err = rc.Read(func(fd uintptr) bool {
		_, _, err := syscall.Recvfrom(int(fd), peek[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		return !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR)
	})
	if err != nil && !isTimeout(err) {
		return nil // leave other errors, such as a closed connection, to Read
	}
	return err
}
