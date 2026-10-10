//go:build race

package portmux

// raceEnabled reports a build with the race detector, which allocates where
// a normal build does not.
const raceEnabled = true
