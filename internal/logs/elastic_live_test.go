package logs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveElasticsearch runs against a real 8.x node when one is listening.
// It checks point-in-time pagination, the exact hostname term, a late line
// inside the open page, and date_nanos.
func TestLiveElasticsearch(t *testing.T) {
	base := os.Getenv("MC_ELASTIC_URL")
	if base == "" {
		base = "http://127.0.0.1:9200"
	}
	base = strings.TrimRight(base, "/")
	client := &http.Client{Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	cancel()
	if err != nil {
		t.Skipf("elasticsearch not available: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode >= 300 || !strings.Contains(string(body), `"number"`) {
		t.Skipf("elasticsearch not available: %s", res.Status)
	}

	// The name stays off the built-in logs data-stream template.
	index := "mc-review-lines"
	es := func(method, path, payload string) string {
		t.Helper()
		var r io.Reader
		if payload != "" {
			r = strings.NewReader(payload)
		}
		req, err := http.NewRequest(method, base+path, r)
		if err != nil {
			t.Fatal(err)
		}
		if payload != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode >= 300 && !(method == http.MethodDelete && res.StatusCode == http.StatusNotFound) {
			t.Fatalf("%s %s: %s: %s", method, path, res.Status, raw)
		}
		return string(raw)
	}
	es(http.MethodDelete, "/"+index, "")
	t.Cleanup(func() {
		req, _ := http.NewRequest(http.MethodDelete, base+"/"+index, nil)
		res, err := client.Do(req)
		if err == nil {
			res.Body.Close()
		}
	})
	es(http.MethodPut, "/"+index, `{
	  "mappings": {"properties": {
	    "@timestamp": {"type": "date"},
	    "nanos": {"type": "date_nanos"},
	    "message": {"type": "text"},
	    "host": {"properties": {"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}}
	  }}
	}`)
	stamp := "2026-10-19T12:00:00.000Z"
	var bulk bytes.Buffer
	write := func(id, ts, nanos, host, msg string) {
		fmt.Fprintf(&bulk, "{\"index\":{\"_id\":%q}}\n", id)
		fmt.Fprintf(&bulk, "{\"@timestamp\":%q,\"nanos\":%q,\"message\":%q,\"host\":{\"name\":%q}}\n", ts, nanos, msg, host)
	}
	write("a", stamp, "2026-10-19T12:00:00.123456789Z", "mbp", "alpha")
	write("b", stamp, "2026-10-19T12:00:00.123456789Z", "mbp-2", "beta")
	write("d", stamp, "2026-10-19T12:00:00.123456789Z", "mbp", "delta")
	write("c", "2026-10-19T12:00:05.000Z", "2026-10-19T12:00:05.000000000Z", "mbp", "gamma")
	es(http.MethodPost, "/"+index+"/_bulk?refresh=true", bulk.String())

	v := View{
		TimeZone: "UTC", MaxLines: 1000, DeviceScoped: true,
		Sources: []Source{{
			Index: 0, Label: "App", MessageField: "message", TimestampField: "@timestamp",
			IndexPattern: index, KQL: `host.name: {{hostname}}`,
		}},
	}
	e := &Engine{Reader: &Elastic{Base: base, HTTP: client}, Now: func() time.Time { return time.Date(2026, 10, 19, 13, 0, 0, 0, time.UTC) }}
	from := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 10, 19, 18, 0, 0, 0, time.UTC)
	var all []string
	cursor := ""
	for n := 0; n < 10; n++ {
		req := RunRequest{View: v, From: from, To: to, Limit: 1, Cursor: cursor, Align: "start", Bind: &Bind{Hostname: "mbp"}}
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
		if len(page.Lines) != 1 {
			t.Fatalf("page %v", msgs(page.Lines))
		}
		all = append(all, page.Lines[0].Message)
		if !page.HasMoreAfter {
			break
		}
		cursor = page.Cursor
	}
	for _, m := range all {
		if m == "beta" {
			t.Fatalf("hostname mbp also returned mbp-2: %v", all)
		}
	}
	if stringsJoin(all) != "alpha delta gamma" && stringsJoin(all) != "delta alpha gamma" {
		t.Fatalf("pages = %v", all)
	}
	seen := map[string]int{}
	for _, m := range all {
		seen[m]++
		if seen[m] > 1 {
			t.Fatalf("duplicate %s in %v", m, all)
		}
	}

	// The open page already holds every line. A document indexed afterwards,
	// with a timestamp between the first and last line, has to come back once.
	open, err := e.Run(context.Background(), RunRequest{
		View: v, From: from, To: to, Limit: 10, Align: "start", Bind: &Bind{Hostname: "mbp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(open.Lines) != 3 {
		t.Fatalf("open page %v", msgs(open.Lines))
	}
	es(http.MethodPost, "/"+index+"/_doc/late?refresh=true", `{"@timestamp":"2026-10-19T12:00:02.000Z","nanos":"2026-10-19T12:00:02.000000001Z","message":"late","host":{"name":"mbp"}}`)
	tail, err := e.Run(context.Background(), RunRequest{
		View: v, Bind: &Bind{Hostname: "mbp"}, Cursor: open.Cursor, Dir: "forward", Extend: true, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stringsJoin(msgs(tail.Lines)) != "late" {
		t.Fatalf("tail = %v, page was %v", msgs(tail.Lines), msgs(open.Lines))
	}

	nanoView := v
	nanoView.Sources = []Source{{
		Index: 0, Label: "App", MessageField: "message", TimestampField: "nanos",
		IndexPattern: index, KQL: `host.name: {{hostname}}`,
	}}
	nano, err := (&Engine{Reader: &Elastic{Base: base, HTTP: client}}).Run(context.Background(), RunRequest{
		View: nanoView, From: from, To: to, Limit: 10, Align: "start", Bind: &Bind{Hostname: "mbp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var alpha time.Time
	for _, line := range nano.Lines {
		if line.Message == "alpha" {
			alpha = line.Timestamp
		}
	}
	want := time.Date(2026, 10, 19, 12, 0, 0, 123456789, time.UTC)
	if !alpha.Equal(want) {
		t.Fatalf("date_nanos = %s, want %s", alpha.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}
