package logs

import (
	"testing"
	"time"
)

func TestZonelessTimestampUsesViewZone(t *testing.T) {
	loc, err := LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	got := ParseTime("2026-10-19 09:40:52", loc)
	want := time.Date(2026, 10, 19, 13, 40, 52, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("zoneless = %s, want %s", got, want)
	}
}

func TestZonedTimestampIgnoresViewZone(t *testing.T) {
	loc, err := LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Fatal(err)
	}
	got := ParseTime("2026-10-19T09:40:52Z", loc)
	want := time.Date(2026, 10, 19, 9, 40, 52, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("zoned = %s, want %s", got, want)
	}
	off := ParseTime("2026-10-19T09:40:52-07:00", loc)
	want = time.Date(2026, 10, 19, 16, 40, 52, 0, time.UTC)
	if !off.Equal(want) {
		t.Fatalf("offset = %s, want %s", off, want)
	}
}

func TestParseWindow(t *testing.T) {
	d, err := ParseWindow("15m")
	if err != nil || d != 15*time.Minute {
		t.Fatal(d, err)
	}
	d, err = ParseWindow("7d")
	if err != nil || d != 7*24*time.Hour {
		t.Fatal(d, err)
	}
	if _, err := ParseWindow("0s"); err == nil {
		t.Fatal("accepted zero")
	}
	if _, err := ParseWindow("90d"); err == nil {
		t.Fatal("accepted 90d")
	}
}
