// Package clock is the time source for scheduling, leases, and promotion soaks.
package clock

import "time"

// Clock returns the current time used by the server.
type Clock interface {
	Now() time.Time
}

// System is the wall clock plus an optional offset (MC_CLOCK_OFFSET).
type System struct {
	Offset time.Duration
}

func (s System) Now() time.Time {
	return time.Now().Add(s.Offset).UTC()
}

// Manual is a test clock.
type Manual struct {
	T time.Time
}

func (m *Manual) Now() time.Time {
	if m.T.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return m.T.UTC()
}

func (m *Manual) Set(t time.Time) { m.T = t.UTC() }

func (m *Manual) Advance(d time.Duration) { m.T = m.Now().Add(d) }
