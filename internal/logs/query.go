package logs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a context anchor is no longer in the view.
var ErrNotFound = errors.New("log line not found")

// Error is a caller-facing validation failure.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errf(format string, args ...any) error {
	return &Error{Msg: fmt.Sprintf(format, args...)}
}

// Engine runs a view through a Reader.
type Engine struct {
	Reader Reader
	Now    func() time.Time
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// RunRequest is one page of a view.
type RunRequest struct {
	View   View
	Bind   *Bind
	From   time.Time
	To     time.Time
	Limit  int
	Cursor string
	// Dir is "forward" or "backward" when Cursor is set.
	Dir string
	// Align is "end" (newest lines) or "start" when Cursor is empty.
	Align string
	// Extend moves the cursor's end to now. Tail uses it.
	Extend bool
}

// Run returns one page. An empty cursor with Align end returns the newest
// lines. Forward continues after them. Backward loads older lines.
func (e *Engine) Run(ctx context.Context, req RunRequest) (Page, error) {
	if e.Reader == nil {
		return Page{}, errf("log view has no reader")
	}
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	kql, loc, err := prepare(req.View, req.Bind)
	if err != nil {
		return Page{}, err
	}
	dev := ""
	if req.View.DeviceScoped && req.Bind != nil {
		dev = req.Bind.Hostname
	}
	if req.Cursor == "" {
		if req.From.IsZero() || req.To.IsZero() || !req.To.After(req.From) {
			return Page{}, errf("time window is empty")
		}
		if req.Align == "start" {
			return e.fromStart(ctx, req, kql, loc, dev)
		}
		return e.latest(ctx, req, kql, loc, dev)
	}
	cur, err := decodeCursor(req.Cursor)
	if err != nil {
		return Page{}, errf("%s", err.Error())
	}
	if len(cur.High) != len(req.View.Sources) {
		return Page{}, errf("cursor does not match this view")
	}
	if dev != cur.Dev {
		return Page{}, errf("cursor does not match this device")
	}
	from := time.Unix(0, cur.From).UTC()
	to := time.Unix(0, cur.To).UTC()
	if req.Extend {
		now := e.now()
		if now.After(to) {
			to = now
			cur.To = now.UnixNano()
		}
	} else {
		if !req.From.IsZero() && req.From.UTC().UnixNano() != cur.From {
			return Page{}, errf("cursor does not match this time window")
		}
		if !req.To.IsZero() && req.To.UTC().UnixNano() != cur.To {
			return Page{}, errf("cursor does not match this time window")
		}
	}
	limit, capped := budget(req.Limit, req.View.MaxLines, cur.N)
	if limit == 0 {
		return Page{Lines: []Line{}, From: from, To: to, Truncated: true}, nil
	}
	if req.Dir == "backward" {
		page, err := e.backward(ctx, req, cur, kql, loc, dev, from, to, limit)
		if err != nil {
			return Page{}, err
		}
		page.Truncated = page.Truncated || capped
		return page, nil
	}
	page, err := e.forward(ctx, req, cur, kql, loc, dev, from, to, limit)
	if err != nil {
		return Page{}, err
	}
	page.Truncated = page.Truncated || capped
	return page, nil
}

// Context returns before+after lines around a line id, across every source.
func (e *Engine) Context(ctx context.Context, view View, bind *Bind, lineID string, before, after int) (Context, error) {
	if e.Reader == nil {
		return Context{}, errf("log view has no reader")
	}
	kql, loc, err := prepare(view, bind)
	if err != nil {
		return Context{}, err
	}
	ref, err := decodeLine(lineID)
	if err != nil {
		return Context{}, errf("%s", err.Error())
	}
	if ref.S < 0 || ref.S >= len(view.Sources) {
		return Context{}, errf("line id does not match this view")
	}
	if before < 0 {
		before = 0
	}
	if after < 0 {
		after = 0
	}
	if before > MaxContext {
		before = MaxContext
	}
	if after > MaxContext {
		after = MaxContext
	}
	anchor := ref.key()
	host := ""
	if bind != nil {
		host = bind.Hostname
	}
	found, err := e.find(ctx, view, kql, loc, host, anchor, ref.Sort)
	if err != nil {
		return Context{}, err
	}
	if found == nil {
		return Context{}, ErrNotFound
	}
	hits := []Hit{*found}
	if before > 0 {
		older, err := e.neighbors(ctx, view, kql, loc, host, anchor, ref.Sort, ref.Pit, before, true)
		if err != nil {
			return Context{}, err
		}
		hits = append(older, hits...)
	}
	focus := 0
	for i, h := range hits {
		if h.Key().Same(anchor) {
			focus = i
			break
		}
	}
	if after > 0 {
		newer, err := e.neighbors(ctx, view, kql, loc, host, anchor, ref.Sort, ref.Pit, after, false)
		if err != nil {
			return Context{}, err
		}
		hits = append(hits, newer...)
	}
	return Context{Lines: project(view, hits), Focus: focus}, nil
}

func (e *Engine) latest(ctx context.Context, req RunRequest, kql []string, loc *time.Location, dev string) (Page, error) {
	limit, capped := budget(req.Limit, req.View.MaxLines, 0)
	if limit == 0 {
		return Page{Lines: []Line{}, From: req.From, To: req.To, Truncated: true}, nil
	}
	batches := make([][]Hit, len(req.View.Sources))
	pits := make([]string, len(req.View.Sources))
	full := false
	for i, src := range req.View.Sources {
		res, err := e.Reader.Search(ctx, baseReq(src, kql[i], loc, dev, req.From, req.To, limit, SearchRequest{Desc: true}))
		if err != nil {
			return Page{}, err
		}
		hits := res.Hits
		if len(hits) > limit {
			hits = hits[len(hits)-limit:]
		}
		if len(hits) == limit {
			full = true
		}
		for j := range hits {
			if hits[j].Pit == "" {
				hits[j].Pit = res.PIT
			}
		}
		batches[i] = hits
		pits[i] = res.PIT
	}
	merged := Merge(batches)
	moreBefore := full
	if len(merged) > limit {
		merged = merged[len(merged)-limit:]
		moreBefore = true
	}
	high := make([]cursorPos, len(req.View.Sources))
	for i, batch := range batches {
		if len(batch) == 0 {
			high[i] = cursorPos{I: i, Seen: true, Empty: true, Pit: pits[i]}
			continue
		}
		high[i] = posFrom(batch[len(batch)-1])
		if high[i].Pit == "" {
			high[i].Pit = pits[i]
		}
	}
	cur := pageCursor{From: req.From.UnixNano(), To: req.To.UnixNano(), Dev: dev, High: high, N: len(merged), MoreBefore: moreBefore}
	if len(merged) > 0 {
		k := storeKey(merged[0])
		cur.Low = &k
	} else {
		moreBefore = false
	}
	token, err := encodeCursor(cur)
	if err != nil {
		return Page{}, err
	}
	return Page{
		Lines: project(req.View, merged), Cursor: token,
		HasMoreBefore: moreBefore, HasMoreAfter: false,
		Truncated: capped, From: req.From, To: req.To,
	}, nil
}

func (e *Engine) fromStart(ctx context.Context, req RunRequest, kql []string, loc *time.Location, dev string) (Page, error) {
	limit, capped := budget(req.Limit, req.View.MaxLines, 0)
	high := make([]cursorPos, len(req.View.Sources))
	for i := range high {
		high[i] = cursorPos{I: i}
	}
	cur := pageCursor{From: req.From.UnixNano(), To: req.To.UnixNano(), Dev: dev, High: high}
	page, err := e.forward(ctx, req, cur, kql, loc, dev, req.From, req.To, limit)
	if err != nil {
		return Page{}, err
	}
	page.Truncated = page.Truncated || capped
	return page, nil
}

func (e *Engine) forward(ctx context.Context, req RunRequest, cur pageCursor, kql []string, loc *time.Location, dev string, from, to time.Time, limit int) (Page, error) {
	batches := make([][]Hit, len(req.View.Sources))
	for i, src := range req.View.Sources {
		sr := baseReq(src, kql[i], loc, dev, from, to, limit, SearchRequest{PIT: cur.High[i].Pit})
		pos := cur.High[i]
		if pos.Seen && !pos.Empty {
			k := pos.key()
			sr.After = &k
			sr.AfterSort = pos.Sort
		}
		res, err := e.Reader.Search(ctx, sr)
		if err != nil {
			return Page{}, err
		}
		hits := res.Hits
		if sr.After != nil {
			hits = strictlyAfter(hits, *sr.After)
		}
		if len(hits) > limit {
			hits = hits[:limit]
		}
		for j := range hits {
			if hits[j].Pit == "" {
				hits[j].Pit = res.PIT
			}
		}
		if res.PIT != "" {
			cur.High[i].Pit = res.PIT
		}
		batches[i] = hits
	}
	merged := Merge(batches)
	if len(merged) > limit {
		merged = merged[:limit]
	}
	taken := map[int]Hit{}
	for _, h := range merged {
		taken[h.Source] = h
		cur.High[h.Source] = posFrom(h)
	}
	more := false
	for i, batch := range batches {
		if len(batch) == 0 {
			if !cur.High[i].Seen {
				cur.High[i] = cursorPos{I: i, Seen: true, Empty: true}
			}
			continue
		}
		last, ok := taken[i]
		consumedAll := ok && last.Key().Same(batch[len(batch)-1].Key())
		if !consumedAll || len(batch) == limit {
			more = true
		}
	}
	if len(merged) > 0 && cur.Low == nil {
		k := storeKey(merged[0])
		cur.Low = &k
	}
	cur.N += len(merged)
	cur.From = from.UnixNano()
	cur.To = to.UnixNano()
	token, err := encodeCursor(cur)
	if err != nil {
		return Page{}, err
	}
	return Page{
		Lines: project(req.View, merged), Cursor: token,
		HasMoreBefore: cur.MoreBefore, HasMoreAfter: more,
		From: from, To: to,
	}, nil
}

func (e *Engine) backward(ctx context.Context, req RunRequest, cur pageCursor, kql []string, loc *time.Location, dev string, from, to time.Time, limit int) (Page, error) {
	if cur.Low == nil {
		cur.MoreBefore = false
		token, err := encodeCursor(cur)
		if err != nil {
			return Page{}, err
		}
		return Page{Lines: []Line{}, Cursor: token, From: from, To: to}, nil
	}
	low := cur.Low.key()
	batches := make([][]Hit, len(req.View.Sources))
	full := false
	for i, src := range req.View.Sources {
		sr := baseReq(src, kql[i], loc, dev, from, low.Time.Add(time.Nanosecond), limit, SearchRequest{Before: &low, PIT: cur.High[i].Pit})
		if i == low.Source {
			sr.BeforeSort = sortFor(cur, low)
		}
		res, err := e.Reader.Search(ctx, sr)
		if err != nil {
			return Page{}, err
		}
		hits := strictlyBefore(res.Hits, low)
		if res.PIT != "" {
			cur.High[i].Pit = res.PIT
		}
		if len(hits) > limit {
			hits = hits[len(hits)-limit:]
		}
		if len(hits) == limit {
			full = true
		}
		batches[i] = hits
	}
	merged := Merge(batches)
	more := full
	if len(merged) > limit {
		merged = merged[len(merged)-limit:]
		more = true
	}
	if len(merged) == 0 {
		more = false
	} else {
		k := storeKey(merged[0])
		cur.Low = &k
	}
	cur.N += len(merged)
	cur.MoreBefore = more
	token, err := encodeCursor(cur)
	if err != nil {
		return Page{}, err
	}
	return Page{
		Lines: project(req.View, merged), Cursor: token,
		HasMoreBefore: cur.MoreBefore, HasMoreAfter: true,
		From: from, To: to,
	}, nil
}

func sortFor(cur pageCursor, low Key) json.RawMessage {
	if cur.Low == nil || cur.Low.S != low.Source {
		return nil
	}
	return cur.Low.Sort
}

func (e *Engine) neighbors(ctx context.Context, view View, kql []string, loc *time.Location, host string, anchor Key, sort json.RawMessage, pit string, n int, before bool) ([]Hit, error) {
	batches := make([][]Hit, len(view.Sources))
	span := 30 * 24 * time.Hour
	for i, src := range view.Sources {
		var sr SearchRequest
		if before {
			sr = baseReq(src, kql[i], loc, host, anchor.Time.Add(-span), anchor.Time.Add(time.Nanosecond), n, SearchRequest{Before: &anchor})
			if i == anchor.Source {
				sr.BeforeSort = sort
				sr.PIT = pit
			}
		} else {
			sr = baseReq(src, kql[i], loc, host, anchor.Time, anchor.Time.Add(span), n, SearchRequest{After: &anchor})
			if i == anchor.Source {
				sr.AfterSort = sort
				sr.PIT = pit
			}
		}
		res, err := e.Reader.Search(ctx, sr)
		if err != nil {
			return nil, err
		}
		hits := res.Hits
		if before {
			hits = strictlyBefore(hits, anchor)
			if len(hits) > n {
				hits = hits[len(hits)-n:]
			}
		} else {
			hits = strictlyAfter(hits, anchor)
			if len(hits) > n {
				hits = hits[:n]
			}
		}
		batches[i] = hits
	}
	merged := Merge(batches)
	if before {
		if len(merged) > n {
			merged = merged[len(merged)-n:]
		}
		return merged, nil
	}
	if len(merged) > n {
		merged = merged[:n]
	}
	return merged, nil
}

func (e *Engine) find(ctx context.Context, view View, kql []string, loc *time.Location, host string, anchor Key, sort json.RawMessage) (*Hit, error) {
	src := view.Sources[anchor.Source]
	sr := baseReq(src, kql[anchor.Source], loc, host, anchor.Time, anchor.Time.Add(time.Nanosecond), MaxSameInstant, SearchRequest{})
	res, err := e.Reader.Search(ctx, sr)
	if err != nil {
		return nil, err
	}
	for _, h := range res.Hits {
		if h.Key().Same(anchor) {
			if len(sort) > 0 && len(h.Sort) == 0 {
				h.Sort = sort
			}
			return &h, nil
		}
	}
	return nil, nil
}

func baseReq(src Source, kql string, loc *time.Location, host string, from, to time.Time, limit int, extra SearchRequest) SearchRequest {
	extra.Source = src
	extra.KQL = kql
	extra.Location = loc
	extra.Host = host
	extra.From = from
	extra.To = to
	extra.Limit = limit
	return extra
}

func strictlyAfter(hits []Hit, k Key) []Hit {
	out := make([]Hit, 0, len(hits))
	for _, h := range hits {
		if k.Before(h.Key()) {
			out = append(out, h)
		}
	}
	return out
}

func strictlyBefore(hits []Hit, k Key) []Hit {
	out := make([]Hit, 0, len(hits))
	for _, h := range hits {
		if h.Key().Before(k) {
			out = append(out, h)
		}
	}
	return out
}

func project(view View, hits []Hit) []Line {
	out := make([]Line, len(hits))
	for i, h := range hits {
		label, color := "", ""
		if h.Source >= 0 && h.Source < len(view.Sources) {
			label = view.Sources[h.Source].Label
			color = view.Sources[h.Source].Color
		}
		out[i] = Line{
			ID: encodeLine(h), Timestamp: h.Time.UTC(), Source: label, Color: color,
			File: h.File, Host: h.Host, Message: h.Msg,
		}
	}
	return out
}

func prepare(view View, bind *Bind) ([]string, *time.Location, error) {
	if len(view.Sources) == 0 || len(view.Sources) > MaxSources {
		return nil, nil, errf("a log view needs between 1 and %d sources", MaxSources)
	}
	if view.DeviceScoped && bind == nil {
		return nil, nil, errf("device_id is required for this log view")
	}
	loc, err := LoadLocation(view.TimeZone)
	if err != nil {
		return nil, nil, errf("%s", err.Error())
	}
	out := make([]string, len(view.Sources))
	for i, src := range view.Sources {
		if src.Index != i {
			return nil, nil, errf("source index mismatch")
		}
		kql := src.KQL
		if UsesPlaceholder(kql) {
			if bind == nil {
				return nil, nil, errf("device_id is required for this log view")
			}
			kql, err = Substitute(kql, *bind)
			if err != nil {
				return nil, nil, errf("%s", err.Error())
			}
		}
		if _, err := Compile(kql, src.MessageField); err != nil {
			return nil, nil, errf("source %s: %s", src.Label, err.Error())
		}
		out[i] = kql
	}
	return out, loc, nil
}

func budget(want, maxLines, already int) (int, bool) {
	if maxLines <= 0 {
		maxLines = 5000
	}
	if maxLines > MaxViewLines {
		maxLines = MaxViewLines
	}
	remain := maxLines - already
	if remain <= 0 {
		return 0, true
	}
	if want <= 0 {
		want = 800
	}
	if want > MaxPage {
		want = MaxPage
	}
	capped := false
	if want > remain {
		want = remain
		capped = true
	}
	return want, capped
}
