package logs

import (
	"context"
	"testing"
	"time"
)

func hit(src int, sec int, seq int64, msg string) Hit {
	return Hit{
		Source: src,
		Time:   time.Unix(int64(sec), 0).UTC(),
		Seq:    seq,
		Tie:    msg,
		File:   "f",
		Host:   "h",
		Msg:    msg,
		Sort:   []byte(`["ok"]`),
	}
}

func view2() View {
	return View{
		Name:     "merged",
		TimeZone: "UTC",
		MaxLines: 1000,
		Sources: []Source{
			{Index: 0, Label: "A", Color: "#111111", MessageField: "message", TimestampField: "@timestamp"},
			{Index: 1, Label: "B", Color: "#222222", MessageField: "message", TimestampField: "@timestamp"},
		},
	}
}

func engine(hits []Hit) *Engine {
	return &Engine{Reader: Memory{Hits: hits}, Now: func() time.Time { return time.Unix(10_000, 0).UTC() }}
}

func msgs(lines []Line) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.Message
	}
	return out
}

func TestMergeOrderEqualTimestamps(t *testing.T) {
	// Same timestamp: source index, then sequence, then tie.
	hits := []Hit{
		hit(1, 10, 2, "b2"),
		hit(0, 10, 5, "a5"),
		hit(1, 10, 1, "b1"),
		hit(0, 10, 5, "a5-tie"), // same seq, tie decides. Wait tie is msg. "a5" < "a5-tie"
		hit(0, 11, 0, "a11"),
		hit(1, 9, 0, "b9"),
	}
	// Fix the duplicate seq 5 on source 0: ties differ.
	hits[3].Tie = "a5-tie"
	hits[1].Tie = "a5"
	e := engine(hits)
	page, err := e.Run(context.Background(), RunRequest{
		View: view2(), From: time.Unix(0, 0), To: time.Unix(100, 0), Limit: 20, Align: "start",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := msgs(page.Lines)
	want := []string{"b9", "a5", "a5-tie", "b1", "b2", "a11"}
	if stringsJoin(got) != stringsJoin(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestPaginationNoGapsOrDuplicates(t *testing.T) {
	var hits []Hit
	for i := 0; i < 10; i++ {
		hits = append(hits, hit(0, i, int64(i), "a"+itoa(i)))
	}
	// Three lines sharing t=4 on source B, interleaved with A.
	for s := int64(1); s <= 3; s++ {
		h := hit(1, 4, s, "b"+itoa(int(s)))
		hits = append(hits, h)
	}
	hits = append(hits, hit(1, 20, 0, "b20"))
	e := engine(hits)
	var all []string
	cursor := ""
	for pageN := 0; pageN < 20; pageN++ {
		req := RunRequest{View: view2(), From: time.Unix(0, 0), To: time.Unix(100, 0), Limit: 3, Cursor: cursor, Align: "start"}
		if cursor != "" {
			req.Dir = "forward"
		}
		page, err := e.Run(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Lines) == 0 {
			if page.HasMoreAfter {
				t.Fatal("empty page claimed more")
			}
			break
		}
		all = append(all, msgs(page.Lines)...)
		if !page.HasMoreAfter {
			break
		}
		cursor = page.Cursor
	}
	want := []string{"a0", "a1", "a2", "a3", "a4", "b1", "b2", "b3", "a5", "a6", "a7", "a8", "a9", "b20"}
	if stringsJoin(all) != stringsJoin(want) {
		t.Fatalf("got %v\nwant %v", all, want)
	}
	seen := map[string]int{}
	for _, m := range all {
		seen[m]++
		if seen[m] > 1 {
			t.Fatalf("duplicate %s", m)
		}
	}
}

func TestLatestThenTailDoesNotRepeat(t *testing.T) {
	var hits []Hit
	for i := 1; i <= 6; i++ {
		hits = append(hits, hit(0, i, 0, "a"+itoa(i)))
	}
	now := time.Unix(100, 0).UTC()
	e := &Engine{Reader: Memory{Hits: hits}, Now: func() time.Time { return now }}
	page, err := e.Run(context.Background(), RunRequest{
		View: view2(), From: time.Unix(0, 0), To: time.Unix(5, 0), Limit: 2, Align: "end",
	})
	if err != nil {
		t.Fatal(err)
	}
	if stringsJoin(msgs(page.Lines)) != "a3 a4" {
		t.Fatalf("latest = %v", msgs(page.Lines))
	}
	// Extend the window. Lines a5 and a6 are new. a4 must not repeat.
	e.Now = func() time.Time { return time.Unix(7, 0).UTC() }
	tail, err := e.Run(context.Background(), RunRequest{View: view2(), Cursor: page.Cursor, Dir: "forward", Extend: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if stringsJoin(msgs(tail.Lines)) != "a5 a6" {
		t.Fatalf("tail = %v", msgs(tail.Lines))
	}
}

func TestBackwardNoGap(t *testing.T) {
	var hits []Hit
	for i := 0; i < 8; i++ {
		hits = append(hits, hit(0, i, 0, "a"+itoa(i)))
		hits = append(hits, hit(1, i, 0, "b"+itoa(i)))
	}
	e := engine(hits)
	latest, err := e.Run(context.Background(), RunRequest{
		View: view2(), From: time.Unix(0, 0), To: time.Unix(100, 0), Limit: 4, Align: "end",
	})
	if err != nil {
		t.Fatal(err)
	}
	back, err := e.Run(context.Background(), RunRequest{
		View: view2(), Cursor: latest.Cursor, Dir: "backward", Limit: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := append(msgs(back.Lines), msgs(latest.Lines)...)
	// Newest 8 of 16 lines. Order is a0,b0,... so the newest are a4,b4,...a7,b7.
	// Latest 4: a6,b6,a7,b7. Previous 4: a4,b4,a5,b5.
	want := []string{"a4", "b4", "a5", "b5", "a6", "b6", "a7", "b7"}
	if stringsJoin(got) != stringsJoin(want) {
		t.Fatalf("got %v want %v\nlatest %v back %v", got, want, msgs(latest.Lines), msgs(back.Lines))
	}
}

func TestContextAroundEqualTimestamps(t *testing.T) {
	hits := []Hit{
		hit(0, 5, 1, "a-before"),
		hit(0, 5, 2, "a-anchor"),
		hit(0, 5, 3, "a-after"),
		hit(1, 5, 0, "b-same"),
		hit(1, 4, 0, "b-earlier"),
		hit(0, 6, 0, "a-later"),
	}
	e := engine(hits)
	page, err := e.Run(context.Background(), RunRequest{
		View: view2(), From: time.Unix(0, 0), To: time.Unix(100, 0), Limit: 20, Align: "start",
	})
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, l := range page.Lines {
		if l.Message == "a-anchor" {
			id = l.ID
		}
	}
	if id == "" {
		t.Fatal(msgs(page.Lines))
	}
	ctx, err := e.Context(context.Background(), view2(), nil, id, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	got := msgs(ctx.Lines)
	// Same timestamp: source 0 (a-after) sorts before source 1 (b-same).
	want := []string{"b-earlier", "a-before", "a-anchor", "a-after", "b-same"}
	if stringsJoin(got) != stringsJoin(want) {
		t.Fatalf("context %v focus %d, full %v", got, ctx.Focus, msgs(page.Lines))
	}
	if ctx.Lines[ctx.Focus].Message != "a-anchor" {
		t.Fatalf("focus %d %v", ctx.Focus, got)
	}
}

func TestDevicePlaceholderRequired(t *testing.T) {
	v := view2()
	v.DeviceScoped = true
	v.Sources[0].KQL = `host.name: {{hostname}}`
	v.Sources[1].KQL = `host.name: {{hostname}}`
	e := engine(nil)
	_, err := e.Run(context.Background(), RunRequest{View: v, From: time.Unix(0, 0), To: time.Unix(10, 0), Align: "end"})
	if err == nil {
		t.Fatal("missing device accepted")
	}
	v.Sources[1].KQL = ""
	_, err = e.Run(context.Background(), RunRequest{
		View: v, Bind: &Bind{Hostname: "mbp"}, From: time.Unix(0, 0), To: time.Unix(10, 0), Align: "end",
	})
	if err == nil {
		t.Fatal("unfiltered source accepted on a device-scoped view")
	}
	v.Sources[1].KQL = `host.name: {{hostname}}`
	_, err = e.Run(context.Background(), RunRequest{
		View: v, Bind: &Bind{Hostname: "a\" OR *"}, From: time.Unix(0, 0), To: time.Unix(10, 0), Align: "end",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMaxLinesCap(t *testing.T) {
	var hits []Hit
	for i := 0; i < 10; i++ {
		hits = append(hits, hit(0, i, 0, itoa(i)))
	}
	v := view2()
	v.MaxLines = 3
	e := engine(hits)
	page, err := e.Run(context.Background(), RunRequest{
		View: v, From: time.Unix(0, 0), To: time.Unix(100, 0), Limit: 100, Align: "start",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Lines) != 3 || !page.Truncated {
		t.Fatalf("len %d truncated %v", len(page.Lines), page.Truncated)
	}
	next, err := e.Run(context.Background(), RunRequest{View: v, Cursor: page.Cursor, Dir: "forward", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Lines) != 0 {
		t.Fatalf("cap did not hold: %v", msgs(next.Lines))
	}
}

func TestForwardDoesNotInventOlderLines(t *testing.T) {
	var hits []Hit
	for i := 0; i < 6; i++ {
		hits = append(hits, hit(0, i, 0, "a"+itoa(i)))
	}
	e := engine(hits)
	first, err := e.Run(context.Background(), RunRequest{
		View: view2(), From: time.Unix(0, 0), To: time.Unix(100, 0), Limit: 2, Align: "start",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.HasMoreBefore || stringsJoin(msgs(first.Lines)) != "a0 a1" {
		t.Fatalf("first %#v %v", first.HasMoreBefore, msgs(first.Lines))
	}
	second, err := e.Run(context.Background(), RunRequest{
		View: view2(), Cursor: first.Cursor, Dir: "forward", Limit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.HasMoreBefore || stringsJoin(msgs(second.Lines)) != "a2 a3" {
		t.Fatalf("forward claimed older lines: before=%v lines=%v", second.HasMoreBefore, msgs(second.Lines))
	}
}

func TestLatestKeepsOlderFlagAcrossTail(t *testing.T) {
	var hits []Hit
	for i := 0; i < 6; i++ {
		hits = append(hits, hit(0, i, 0, "a"+itoa(i)))
	}
	e := engine(hits)
	latest, err := e.Run(context.Background(), RunRequest{
		View: view2(), From: time.Unix(0, 0), To: time.Unix(100, 0), Limit: 2, Align: "end",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !latest.HasMoreBefore || stringsJoin(msgs(latest.Lines)) != "a4 a5" {
		t.Fatalf("latest %#v %v", latest.HasMoreBefore, msgs(latest.Lines))
	}
	e.Now = func() time.Time { return time.Unix(200, 0).UTC() }
	tail, err := e.Run(context.Background(), RunRequest{
		View: view2(), Cursor: latest.Cursor, Dir: "forward", Extend: true, Limit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !tail.HasMoreBefore {
		t.Fatal("tail dropped the older-lines flag")
	}
	if len(tail.Lines) != 0 {
		t.Fatalf("tail invented lines %v", msgs(tail.Lines))
	}
}

func stringsJoin(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
