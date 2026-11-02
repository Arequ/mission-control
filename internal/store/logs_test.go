package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Arequ/mission-control/internal/clock"
	"github.com/Arequ/mission-control/internal/model"
)

func TestSeededLogViewMergeTailContextAndAudit(t *testing.T) {
	s := newCoverageStore(t)
	ctx := context.Background()
	if err := s.seedLogViews(ctx); err != nil {
		t.Fatal(err)
	}
	clk := &clock.Manual{T: time.Unix(1_700_000_000, 0).UTC()}
	s.SetClock(clk)
	id := enrollDevice(t, s, "dev-log", "C02QUOTE\"OR", "11111111-1111-1111-1111-111111111111", "aa:bb:cc:dd:ee:ff", `mbp" OR *`, "ava")
	p := model.Principal{Kind: "api", ID: "tester", Name: "tester"}
	views, err := s.ListLogViews(ctx, "Endpoint logs")
	if err != nil || len(views) != 1 {
		t.Fatalf("%v %+v", err, views)
	}
	view := views[0]
	if view.ElasticAPIKey != "" || view.Reader != "" {
		t.Fatalf("public view leaked reader or key: %+v", view)
	}
	loaded, err := s.loadLogView(ctx, view.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Reader != "seed" || loaded.ElasticAPIKey != "" {
		t.Fatalf("seed reader %+v", loaded.Reader)
	}
	page, err := s.RunLogView(ctx, p, view.ID, model.LogRun{DeviceID: id, Limit: 30, Align: "end"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Lines) < 10 || !page.HasMoreBefore {
		t.Fatalf("page %d before %v", len(page.Lines), page.HasMoreBefore)
	}
	var prev time.Time
	seen := map[string]bool{}
	for _, line := range page.Lines {
		if line.Host != `mbp" OR *` {
			t.Fatalf("host %q", line.Host)
		}
		if seen[line.ID] {
			t.Fatalf("duplicate %s", line.Message)
		}
		seen[line.ID] = true
		if !prev.IsZero() && line.Timestamp.Before(prev) {
			t.Fatal("out of order")
		}
		prev = line.Timestamp
	}
	older, err := s.RunLogView(ctx, p, view.ID, model.LogRun{DeviceID: id, Cursor: page.Cursor, Dir: "backward", Limit: 30})
	if err != nil {
		t.Fatal(err)
	}
	if len(older.Lines) == 0 {
		t.Fatal("backward page empty")
	}
	for _, line := range older.Lines {
		if seen[line.ID] {
			t.Fatalf("overlap %s", line.Message)
		}
		if line.Timestamp.After(page.Lines[0].Timestamp) {
			t.Fatalf("backward returned a newer line %s", line.Message)
		}
	}
	clk.Advance(2 * time.Minute)
	tail, err := s.TailLogView(ctx, p, view.ID, model.LogRun{DeviceID: id, Cursor: page.Cursor, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(tail.Lines) == 0 {
		t.Fatal("tail added nothing")
	}
	for _, line := range tail.Lines {
		if seen[line.ID] {
			t.Fatalf("tail repeated %s", line.Message)
		}
	}
	ctxLines, err := s.ContextLogView(ctx, p, view.ID, page.Lines[len(page.Lines)/2].ID, id, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if ctxLines.Focus < 0 || ctxLines.Focus >= len(ctxLines.Lines) || ctxLines.Lines[ctxLines.Focus].ID != page.Lines[len(page.Lines)/2].ID {
		t.Fatalf("focus %+v", ctxLines)
	}
	var audit string
	if err := s.Pool().QueryRow(ctx, `SELECT coalesce(string_agg(action || ' ' || detail::text, '\n'), '') FROM audit_log WHERE resource_type='log_view'`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(audit, `"op": "run"`) || !strings.Contains(audit, `"op": "tail"`) || !strings.Contains(audit, `"op": "context"`) {
		t.Fatalf("audit %s", audit)
	}
	if strings.Contains(audit, "super-secret") || strings.Contains(audit, `mbp\" OR`) {
		t.Fatalf("audit leaked a secret or a substituted query: %s", audit)
	}
	errorsView, err := s.ListLogViews(ctx, "osquery errors")
	if err != nil || len(errorsView) != 1 {
		t.Fatal(err)
	}
	errPage, err := s.RunLogView(ctx, p, errorsView[0].ID, model.LogRun{DeviceID: id, Limit: 20, Align: "end"})
	if err != nil {
		t.Fatal(err)
	}
	if len(errPage.Lines) == 0 {
		t.Fatal("osquery errors empty")
	}
	for _, line := range errPage.Lines {
		if !strings.Contains(line.Message, "watcher.cpp") && !strings.Contains(line.Message, "distributed.cpp") {
			t.Fatalf("info line in error view: %s", line.Message)
		}
	}
	if _, err := s.UpdateLogView(ctx, p, view.ID, model.LogView{
		Name: view.Name, Description: "still seeded", DefaultWindow: "1h", MaxLines: 5000,
		DeviceScoped: true, TimeZone: "UTC", ManagedBy: "terraform", Sources: loaded.Sources,
	}); err != nil {
		t.Fatal(err)
	}
	after, err := s.loadLogView(ctx, view.ID)
	if err != nil || after.Reader != "seed" || after.Description != "still seeded" {
		t.Fatalf("update dropped seed reader: %+v %v", after.Reader, err)
	}
}
