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
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && len(s) >= 10 {
		return parseUnix(n, len(s))
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
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
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func parseNumericTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if strings.Contains(s, ".") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return time.Time{}
		}
		return parseUnix(int64(f), digits(int64(f)))
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return parseUnix(n, len(strings.TrimPrefix(s, "-")))
}

func digits(n int64) int {
	if n < 0 {
		n = -n
	}
	d := 1
	for n >= 10 {
		n /= 10
		d++
	}
	return d
}

func parseUnix(n int64, width int) time.Time {
	switch {
	case width >= 19:
		return time.Unix(0, n).UTC()
	case width >= 16:
		return time.UnixMicro(n).UTC()
	case width >= 13:
		return time.UnixMilli(n).UTC()
	case width >= 10:
		return time.Unix(n, 0).UTC()
	default:
		return time.Time{}
	}
}
