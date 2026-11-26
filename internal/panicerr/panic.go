// Package panicerr captures panics at package callback boundaries.
package panicerr

import (
	"fmt"
	"runtime/debug"
)

// PanicError holds the value and stack of a recovered panic.
type PanicError struct {
	// Value is the value passed to panic.
	Value any
	// Stack is the stack of the goroutine that panicked.
	Stack []byte
}

// New captures the stack of the goroutine that recovered value.
func New(value any) *PanicError { return &PanicError{Value: value, Stack: debug.Stack()} }

func (e *PanicError) Error() string {
	return fmt.Sprintf("portmux: callback panic: %v", e.Value)
}
