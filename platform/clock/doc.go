// Package clock provides a time abstraction for testability.
//
// Use [RealClock] in production and [FixedClock] in tests:
//
//	var clk clock.Clock = clock.RealClock{}
//	if testing {
//	    clk = clock.FixedClock{T: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
//	}
//	now := clk.Now()
package clock
