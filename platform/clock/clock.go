package clock

import "time"

// Clock abstracts time for testability.
type Clock interface {
	Now() time.Time
}

// RealClock returns the actual current time.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

// FixedClock returns a fixed time for testing.
type FixedClock struct {
	T time.Time
}

func (c FixedClock) Now() time.Time { return c.T }
