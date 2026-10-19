package logs

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseWindow parses a view's default window. Days are supported; the span
// must be between one minute and thirty days.
func ParseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return time.Hour, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 1 || n > 30 {
			return 0, fmt.Errorf("window must be between 1m and 30d")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < time.Minute || d > 30*24*time.Hour {
		return 0, fmt.Errorf("window must be between 1m and 30d")
	}
	return d, nil
}

// LoadLocation loads an IANA zone. Blank means UTC.
func LoadLocation(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.EqualFold(name, "UTC") || strings.EqualFold(name, "Z") {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("time zone %q is not an IANA name", name)
	}
	return loc, nil
}

// ParseTime parses a log timestamp. Values that already carry an offset are
// absolute. Values without an offset are read in loc, then returned in UTC.
func ParseTime(v any, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	switch t := v.(type) {
	case string:
		return parseTimeString(t, loc)
	case jsonNumber:
		return parseNumericTime(t.String())
	case int64:
		return parseNumericTime(strconv.FormatInt(t, 10))
	case float64:
		return parseNumericTime(strconv.FormatFloat(t, 'f', -1, 64))
	default:
		return time.Time{}
	}
}

// jsonNumber is implemented by encoding/json.Number without importing it here
// as a type switch target via a tiny interface.
type jsonNumber interface {
	String() string
	Float64() (float64, error)
}

func parseTimeString(s string, loc *time.Location) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if looksNumericTime(s) {
		return parseNumericTime(s)
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.000000000Z07:00",
		"2006-01-02 15:04:05Z07:00",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05.000000000",
		"2006-01-02T15:04:05.000000000",
		"2006-01-02 15:04:05.000",
		"2006-01-02T15:04:05.000",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	} {
		if t, ok := parseCivil(s, layout, loc); ok {
			return t
		}
	}
	return time.Time{}
}

func looksNumericTime(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' {
		i++
	}
	digits := 0
	dot := false
	for ; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			digits++
		case s[i] == '.' && !dot:
			dot = true
		default:
			return false
		}
	}
	return digits >= 10
}

func parseNumericTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	neg := strings.HasPrefix(s, "-")
	raw := strings.TrimPrefix(s, "-")
	whole, frac, hasFrac := strings.Cut(raw, ".")
	if whole == "" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}
	}
	if neg {
		n = -n
	}
	base := parseUnix(n, len(whole))
	if base.IsZero() {
		return time.Time{}
	}
	if !hasFrac || frac == "" {
		return base
	}
	return base.Add(time.Duration(fracNanos(frac, unitNanos(n, len(whole)))))
}

// parseCivil reads a zoneless timestamp in loc. A clock time that exists,
// including the repeated hour when DST falls back, uses the first instant.
// A clock time that falls in the spring-forward gap is moved forward by the
// skipped duration, so 02:30 in a one-hour gap is stored as 03:30.
func parseCivil(s, layout string, loc *time.Location) (time.Time, bool) {
	civil, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}, false
	}
	y, m, d := civil.Date()
	h, min, sec := civil.Clock()
	ns := civil.Nanosecond()
	local := time.Date(y, m, d, h, min, sec, ns, loc)
	ly, lm, ld := local.Date()
	lh, lmin, lsec := local.Clock()
	if ly == y && lm == m && ld == d && lh == h && lmin == min && lsec == sec && local.Nanosecond() == ns {
		return local.UTC(), true
	}
	got := time.Date(ly, lm, ld, lh, lmin, lsec, local.Nanosecond(), time.UTC)
	want := time.Date(y, m, d, h, min, sec, ns, time.UTC)
	return local.Add(want.Sub(got)).UTC(), true
}

func parseUnix(n int64, width int) time.Time {
	abs := n
	if abs < 0 {
		abs = -abs
	}
	switch {
	case width >= 19 || abs >= 1_000_000_000_000_000_000:
		return time.Unix(0, n).UTC()
	case width >= 16 || abs >= 1_000_000_000_000_000:
		return time.UnixMicro(n).UTC()
	case width >= 11 || abs >= 100_000_000_000:
		// 11- and 12-digit values are milliseconds from the 1970s through 2001.
		// Reading them as seconds lands in year 5000.
		return time.UnixMilli(n).UTC()
	case width >= 10 || abs >= 1_000_000_000:
		return time.Unix(n, 0).UTC()
	default:
		return time.Time{}
	}
}

func unitNanos(n int64, width int) int64 {
	abs := n
	if abs < 0 {
		abs = -abs
	}
	switch {
	case width >= 19 || abs >= 1_000_000_000_000_000_000:
		return 1
	case width >= 16 || abs >= 1_000_000_000_000_000:
		return int64(time.Microsecond)
	case width >= 11 || abs >= 100_000_000_000:
		return int64(time.Millisecond)
	default:
		return int64(time.Second)
	}
}

func fracNanos(frac string, unit int64) int64 {
	if frac == "" || unit <= 0 {
		return 0
	}
	if len(frac) > 9 {
		frac = frac[:9]
	}
	for len(frac) < 9 {
		frac += "0"
	}
	v, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return 0
	}
	return v * unit / 1_000_000_000
}
