package logs

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestTailLateLineInsidePage is the multi-source hole: a line that arrives
// after the first read, with a timestamp inside the page the user is looking
// at, is earlier than the merged cursor and later than nothing the backward
// page will revisit. It must show up once on tail.
func TestTailLateLineInsidePage(t *testing.T) {
	hits := []Hit{
		hit(0, 10, 0, "a10"),
		hit(0, 40, 0, "a40"),
		hit(0, 50, 0, "a50"),
		hit(1, 20, 0, "b20"),
		hit(1, 30, 0, "b30"),
		hit(1, 45, 0, "b45"),
	}
	mem := &Memory{Hits: append([]Hit(nil), hits...)}
	e := &Engine{Reader: mem, Now: func() time.Time { return time.Unix(100, 0).UTC() }}
	page, err := e.Run(context.Background(), RunRequest{
		View: view2(), From: time.Unix(0, 0), To: time.Unix(100, 0), Limit: 3, Align: "end",
	})
	if err != nil {
		t.Fatal(err)
	}
	if stringsJoin(msgs(page.Lines)) != "a40 b45 a50" {
		t.Fatalf("page %v", msgs(page.Lines))
	}
	mem.Hits = append(mem.Hits, hit(1, 42, 0, "b42-late"))
	tail, err := e.Run(context.Background(), RunRequest{
		View: view2(), Cursor: page.Cursor, Dir: "forward", Extend: true, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := msgs(tail.Lines)
	if stringsJoin(got) != "b42-late" {
		t.Fatalf("tail = %v, want the late line once", got)
	}
	back, err := e.Run(context.Background(), RunRequest{
		View: view2(), Cursor: tail.Cursor, Dir: "backward", Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs(back.Lines) {
		if m == "b42-late" {
			t.Fatalf("backward repeated the late line: %v", msgs(back.Lines))
		}
	}
}

// TestTailSkipsLineBeforePageLow is a line that shares the page's oldest
// timestamp but sorts before that line. It was outside the newest page. Tail
// must leave it for backward instead of appending it under the newest line.
func TestTailSkipsLineBeforePageLow(t *testing.T) {
	hits := []Hit{
		hit(0, 10, 0, "a10-before"),
		hit(1, 10, 0, "b10"),
		hit(0, 40, 0, "a40"),
		hit(1, 50, 0, "b50"),
	}
	mem := &Memory{Hits: append([]Hit(nil), hits...)}
	e := &Engine{Reader: mem, Now: func() time.Time { return time.Unix(100, 0).UTC() }}
	page, err := e.Run(context.Background(), RunRequest{
		View: view2(), From: time.Unix(0, 0), To: time.Unix(100, 0), Limit: 3, Align: "end",
	})
	if err != nil {
		t.Fatal(err)
	}
	if stringsJoin(msgs(page.Lines)) != "b10 a40 b50" {
		t.Fatalf("page %v", msgs(page.Lines))
	}
	tail, err := e.Run(context.Background(), RunRequest{
		View: view2(), Cursor: page.Cursor, Dir: "forward", Extend: true, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tail.Lines) != 0 {
		t.Fatalf("tail = %v, want nothing already outside the page", msgs(tail.Lines))
	}
	back, err := e.Run(context.Background(), RunRequest{
		View: view2(), Cursor: page.Cursor, Dir: "backward", Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stringsJoin(msgs(back.Lines)) != "a10-before" {
		t.Fatalf("backward = %v", msgs(back.Lines))
	}
}

// TestElasticTiebreakPagesNoDupes walks a source whose equal timestamps are
// ordered by _shard_doc, not by _id. Resuming from the reordered _id drops
// or repeats lines.
func TestElasticTiebreakPagesNoDupes(t *testing.T) {
	type doc struct {
		id    string
		shard int
		msg   string
	}
	docs := []doc{
		{"e", 1, "e"},
		{"c", 2, "c"},
		{"a", 3, "a"},
		{"d", 4, "d"},
		{"b", 5, "b"},
	}
	pitID := "pit-tie"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_pit") {
			_, _ = io.WriteString(w, `{"id":"pit-tie"}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		if pit, _ := req["pit"].(map[string]any); pit["id"] != pitID {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"type":"search_context_missing_exception","reason":"No search context found for id"}}`)
			return
		}
		pitID = "pit-tie-2"
		start := 0
		if sa, ok := req["search_after"].([]any); ok && len(sa) >= 2 {
			shard, _ := sa[1].(float64)
			for i, d := range docs {
				if d.shard > int(shard) {
					start = i
					break
				}
				start = len(docs)
			}
		}
		size := 10
		if s, ok := req["size"].(float64); ok && int(s) > 0 {
			size = int(s)
		}
		end := start + size
		if end > len(docs) {
			end = len(docs)
		}
		var b strings.Builder
		b.WriteString(`{"pit_id":"pit-tie-2","hits":{"hits":[`)
		for i := start; i < end; i++ {
			if i > start {
				b.WriteByte(',')
			}
			d := docs[i]
			b.WriteString(`{"_id":"` + d.id + `","sort":[1000,` + itoa(d.shard) + `],"_source":{"@timestamp":"2026-10-19T00:00:01Z","message":"` + d.msg + `"}}`)
		}
		b.WriteString(`]}}`)
		_, _ = io.WriteString(w, b.String())
	}))
	defer srv.Close()
	e := &Engine{Reader: &Elastic{Base: srv.URL, HTTP: srv.Client()}, Now: func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }}
	v := View{TimeZone: "UTC", MaxLines: 100, Sources: []Source{{
		Index: 0, Label: "A", MessageField: "message", TimestampField: "@timestamp", IndexPattern: "logs-*",
	}}}
	var all []string
	cursor := ""
	for n := 0; n < 10; n++ {
		req := RunRequest{View: v, From: time.Unix(0, 0), To: time.Unix(2_000_000_000, 0), Limit: 2, Cursor: cursor, Align: "start"}
		if cursor != "" {
			req.Dir = "forward"
		}
		page, err := e.Run(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Lines) == 0 {
			break
		}
		all = append(all, msgs(page.Lines)...)
		if !page.HasMoreAfter {
			break
		}
		cursor = page.Cursor
	}
	if stringsJoin(all) != "e c a d b" {
		t.Fatalf("order %v", all)
	}
	seen := map[string]int{}
	for _, m := range all {
		seen[m]++
		if seen[m] > 1 {
			t.Fatalf("duplicate %s in %v", m, all)
		}
	}
}

// TestElasticPITRenewalKeepsTheRest expires the point-in-time on the second
// page and hands back a new snapshot whose _shard_doc order is not the old
// one. Resuming with the stale sort tuple drops lines that were not shown
// and repeats lines that were.
func TestElasticPITRenewalKeepsTheRest(t *testing.T) {
	type doc struct {
		id    string
		shard int
		msg   string
	}
	docs := []doc{
		{"e", 1, "e"},
		{"c", 2, "c"},
		{"a", 3, "a"},
		{"d", 4, "d"},
		{"b", 5, "b"},
	}
	opened := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.Contains(r.URL.Path, "/_pit") {
			opened++
			_, _ = io.WriteString(w, `{"id":"pit-`+itoa(opened)+`"}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		pit, _ := req["pit"].(map[string]any)
		id, _ := pit["id"].(string)
		if _, ok := req["search_after"]; ok && id == "pit-1" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"type":"search_context_missing_exception","reason":"No search context found for id"}}`)
			return
		}
		// The renewed snapshot assigns _shard_doc in id order, the reverse of
		// the first snapshot's order.
		order := docs
		if id != "pit-1" {
			order = []doc{
				{"a", 1, "a"},
				{"b", 2, "b"},
				{"c", 3, "c"},
				{"d", 4, "d"},
				{"e", 5, "e"},
			}
		}
		start := 0
		if sa, ok := req["search_after"].([]any); ok && len(sa) >= 2 {
			shard, _ := sa[1].(float64)
			start = len(order)
			for i, d := range order {
				if d.shard > int(shard) {
					start = i
					break
				}
			}
		}
		size := len(order)
		if s, ok := req["size"].(float64); ok && int(s) > 0 {
			size = int(s)
		}
		end := start + size
		if end > len(order) {
			end = len(order)
		}
		var b strings.Builder
		b.WriteString(`{"pit_id":"` + id + `","hits":{"hits":[`)
		for i := start; i < end; i++ {
			if i > start {
				b.WriteByte(',')
			}
			d := order[i]
			b.WriteString(`{"_id":"` + d.id + `","sort":[1000,` + itoa(d.shard) + `],"_source":{"@timestamp":"2026-10-19T00:00:01Z","message":"` + d.msg + `"}}`)
		}
		b.WriteString(`]}}`)
		_, _ = io.WriteString(w, b.String())
	}))
	defer srv.Close()
	e := &Engine{Reader: &Elastic{Base: srv.URL, HTTP: srv.Client()}, Now: func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }}
	v := View{TimeZone: "UTC", MaxLines: 100, Sources: []Source{{
		Index: 0, Label: "A", MessageField: "message", TimestampField: "@timestamp", IndexPattern: "logs-*",
	}}}
	var all []string
	cursor := ""
	for n := 0; n < 10; n++ {
		req := RunRequest{View: v, From: time.Unix(0, 0), To: time.Unix(2_000_000_000, 0), Limit: 2, Cursor: cursor, Align: "start"}
		if cursor != "" {
			req.Dir = "forward"
		}
		page, err := e.Run(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Lines) == 0 {
			break
		}
		all = append(all, msgs(page.Lines)...)
		if !page.HasMoreAfter {
			break
		}
		cursor = page.Cursor
	}
	seen := map[string]int{}
	for _, m := range all {
		seen[m]++
		if seen[m] > 1 {
			t.Fatalf("duplicate %s in %v", m, all)
		}
	}
	for _, want := range []string{"e", "c", "a", "d", "b"} {
		if seen[want] != 1 {
			t.Fatalf("missing %s in %v", want, all)
		}
	}
}

func TestElasticBeforeUnderfetchesSameTimestamp(t *testing.T) {
	// Ten hits share the anchor instant. Desc page of 3 is the three highest
	// sequences, all strictly after the anchor (seq 4). The earlier sequences
	// exist and must still be returned.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_pit") {
			_, _ = io.WriteString(w, `{"id":"pit"}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		// sequences 1..10 at the same timestamp, ascending shard = seq
		seqs := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		start := len(seqs) - 1
		if sa, ok := req["search_after"].([]any); ok && len(sa) >= 2 {
			shard, _ := sa[1].(float64)
			start = -1
			for i := len(seqs) - 1; i >= 0; i-- {
				if seqs[i] < int(shard) {
					start = i
					break
				}
			}
		}
		size := 3
		if s, ok := req["size"].(float64); ok && int(s) > 0 && int(s) < 100 {
			size = int(s)
		}
		var b strings.Builder
		b.WriteString(`{"pit_id":"pit","hits":{"hits":[`)
		wrote := 0
		for i := start; i >= 0 && wrote < size; i-- {
			if wrote > 0 {
				b.WriteByte(',')
			}
			seq := seqs[i]
			b.WriteString(`{"_id":"s` + itoa(seq) + `","sort":[1000,` + itoa(seq) + `],"_source":{"@timestamp":"2026-10-19T00:00:01Z","message":"m` + itoa(seq) + `","log":{"file":{"offset":` + itoa(seq) + `}}}}`)
			wrote++
		}
		b.WriteString(`]}}`)
		_, _ = io.WriteString(w, b.String())
	}))
	defer srv.Close()
	anchor := Key{Time: time.Date(2026, 10, 19, 0, 0, 1, 0, time.UTC), Source: 0, Seq: 4, Tie: "s4"}
	e := &Elastic{Base: srv.URL, HTTP: srv.Client()}
	res, err := e.Search(context.Background(), SearchRequest{
		Source: Source{
			Index: 0, IndexPattern: "logs-*", MessageField: "message",
			TimestampField: "@timestamp", SequenceField: "log.file.offset",
		},
		Location: time.UTC, From: time.Unix(0, 0), To: time.Unix(2_000_000_000, 0), Limit: 3,
		Before: &anchor,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(res.Hits))
	for i, h := range res.Hits {
		got[i] = h.Msg
	}
	if stringsJoin(got) != "m1 m2 m3" {
		t.Fatalf("before = %v, want the three sequences below the anchor", got)
	}
}

func TestParseEpochWidthsAndFraction(t *testing.T) {
	cases := []struct {
		in   any
		want time.Time
	}{
		{"1700000000", time.Unix(1700000000, 0).UTC()},
		{"1700000000000", time.UnixMilli(1700000000000).UTC()},
		{"1700000000000000", time.UnixMicro(1700000000000000).UTC()},
		{"1700000000000000000", time.Unix(0, 1700000000000000000).UTC()},
		// 12-digit millis: 2001-09-09 is 1e12; this is just before that.
		{"999999999999", time.UnixMilli(999999999999).UTC()},
		{"1700000000.25", time.Unix(1700000000, 250000000).UTC()},
	}
	for _, tc := range cases {
		got := ParseTime(tc.in, time.UTC)
		if !got.Equal(tc.want) {
			t.Errorf("ParseTime(%v) = %s, want %s", tc.in, got.UTC().Format(time.RFC3339Nano), tc.want.Format(time.RFC3339Nano))
		}
	}
}

func TestSpringForwardGapIsNotFiledAnHourEarly(t *testing.T) {
	loc, err := LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	got := ParseTime("2026-03-08 02:30:00", loc)
	// 02:30 does not exist. The clock jumped to 03:00, so 02:30 belongs at 03:30 EDT.
	want := time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("gap = %s, want %s", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
	// The overlap keeps the first instant (EDT, 05:30Z), not the repeated EST hour.
	fall := ParseTime("2026-11-01 01:30:00", loc)
	wantFall := time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC)
	if !fall.Equal(wantFall) {
		t.Fatalf("overlap = %s, want %s", fall.Format(time.RFC3339Nano), wantFall.Format(time.RFC3339Nano))
	}
}
