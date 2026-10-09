//go:build !(linux || android || darwin || ios || freebsd || netbsd || openbsd || windows)

package portmux

import "net"

// waitReadable returns at once: on this platform the read buffer is taken
// before the first read.
func waitReadable(net.Conn) error { return nil }
