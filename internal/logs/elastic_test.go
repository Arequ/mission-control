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

func TestElasticSearchAfterAndPIT(t *testing.T) {
	var bodies []string
	var sawKey bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_pit") {
			_, _ = io.WriteString(w, `{"id":"pit-1"}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		if r.Header.Get("Authorization") != "ApiKey test-key" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if strings.Contains(string(raw), "test-key") {
			t.Errorf("api key leaked into the body")
		}
		sawKey = true
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		if _, ok := req["pit"]; !ok {
			t.Errorf("missing pit: %s", raw)
		}
		if strings.Contains(string(raw), "query_string") {
			t.Errorf("query_string in %s", raw)
		}
		_, _ = io.WriteString(w, `{"hits":{"hits":[
			{"_id":"1","sort":[1000,1],"_source":{"@timestamp":"2026-10-19T00:00:01Z","message":"one","log":{"file":{"path":"/var/log/a"}}}},
			{"_id":"2","sort":[2000,2],"_source":{"@timestamp":"2026-10-19T00:00:02Z","message":"two","host":{"name":"mbp"}}}
		]}}`)
	}))
	defer srv.Close()
	e := &Elastic{Base: srv.URL, APIKey: "test-key", HTTP: srv.Client()}
	res, err := e.Search(context.Background(), SearchRequest{
		Source: Source{
			Index: 0, Label: "Munki", IndexPattern: "logs-munki-*",
			MessageField: "message", TimestampField: "@timestamp",
			FileField: "log.file.path", HostField: "host.name",
		},
		KQL: `host.name: "mbp"`, Location: time.UTC,
		From: time.Unix(0, 0), To: time.Unix(10, 0), Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawKey || len(res.Hits) != 2 || res.PIT != "pit-1" {
		t.Fatalf("hits %d pit %q", len(res.Hits), res.PIT)
	}
	if res.Hits[0].Msg != "one" || res.Hits[0].File != "/var/log/a" || res.Hits[1].Host != "mbp" {
		t.Fatalf("%#v", res.Hits)
	}
	if len(res.Hits[1].Sort) == 0 {
		t.Fatal("missing sort")
	}
	// Second page must send the sort tuple back and reuse the PIT.
	res.Hits[1].Pit = res.PIT
	key := res.Hits[1].Key()
	_, err = e.Search(context.Background(), SearchRequest{
		Source: Source{
			Index: 0, Label: "Munki", IndexPattern: "logs-munki-*",
			MessageField: "message", TimestampField: "@timestamp",
		},
		KQL: "", From: time.Unix(0, 0), To: time.Unix(10, 0), Limit: 10,
		PIT: res.PIT, After: &key, AfterSort: res.Hits[1].Sort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bodies[len(bodies)-1], `"search_after":[2000,2]`) {
		t.Fatalf("search_after missing: %s", bodies[len(bodies)-1])
	}
}

func TestElasticBeforeKeepsEarlierSequenceAtSameTime(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_pit") {
			_, _ = io.WriteString(w, `{"id":"pit"}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		_, _ = io.WriteString(w, `{"hits":{"hits":[
			{"_id":"early","sort":[1000,1],"_source":{"@timestamp":"2026-10-19T00:00:01Z","message":"early","log":{"file":{"offset":1}}}},
			{"_id":"anchor","sort":[1000,2],"_source":{"@timestamp":"2026-10-19T00:00:01Z","message":"anchor","log":{"file":{"offset":2}}}}
		]}}`)
	}))
	defer srv.Close()
	anchor := Key{Time: time.Date(2026, 10, 19, 0, 0, 1, 0, time.UTC), Source: 0, Seq: 2, Tie: "anchor"}
	e := &Elastic{Base: srv.URL, APIKey: "k", HTTP: srv.Client()}
	res, err := e.Search(context.Background(), SearchRequest{
		Source: Source{
			Index: 0, IndexPattern: "logs-*", MessageField: "message",
			TimestampField: "@timestamp", SequenceField: "log.file.offset",
		},
		Location: time.UTC, From: time.Unix(0, 0), To: time.Unix(2_000_000_000, 0), Limit: 10,
		Before: &anchor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"lte"`) {
		t.Fatalf("same-source before dropped the anchor instant: %s", body)
	}
	if len(res.Hits) != 1 || res.Hits[0].Msg != "early" || res.Hits[0].Seq != 1 {
		t.Fatalf("%#v", res.Hits)
	}
}

func TestElasticContinuesAfterUnparsedTimestamp(t *testing.T) {
	searches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_pit") {
			_, _ = io.WriteString(w, `{"id":"pit"}`)
			return
		}
		searches++
		raw, _ := io.ReadAll(r.Body)
		if searches == 1 {
			if strings.Contains(string(raw), "search_after") {
				t.Errorf("first page used search_after: %s", raw)
			}
			_, _ = io.WriteString(w, `{"hits":{"hits":[{"_id":"bad","sort":[1],"_source":{"@timestamp":"not-a-time","message":"skip"}}]}}`)
			return
		}
		if !strings.Contains(string(raw), `"search_after":[1]`) {
			t.Errorf("second page did not advance past the bad hit: %s", raw)
		}
		_, _ = io.WriteString(w, `{"hits":{"hits":[{"_id":"good","sort":[2],"_source":{"@timestamp":"2026-10-19T00:00:02Z","message":"kept"}}]}}`)
	}))
	defer srv.Close()
	e := &Elastic{Base: srv.URL, HTTP: srv.Client()}
	res, err := e.Search(context.Background(), SearchRequest{
		Source:   Source{Index: 0, IndexPattern: "logs-*", MessageField: "message", TimestampField: "@timestamp"},
		Location: time.UTC, From: time.Unix(0, 0), To: time.Unix(2_000_000_000, 0), Limit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 1 || res.Hits[0].Msg != "kept" {
		t.Fatalf("%#v", res.Hits)
	}
}

func TestSeedErrorViewDropsInfoLines(t *testing.T) {
	v := View{
		TimeZone: "UTC", MaxLines: 1000,
		Sources: []Source{{
			Index: 0, Label: "osquery", MessageField: "message", TimestampField: "@timestamp",
			KQL: `host.name: {{hostname}} and log.level: "error"`,
		}},
	}
	to := time.Unix(1_700_000_000, 0).UTC()
	e := &Engine{Reader: Seed{}, Now: func() time.Time { return to }}
	page, err := e.Run(context.Background(), RunRequest{
		View: v, Bind: &Bind{Hostname: "mbp"}, From: to.Add(-time.Hour), To: to, Limit: 40, Align: "end",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Lines) < 5 {
		t.Fatalf("too few errors: %d", len(page.Lines))
	}
	for _, line := range page.Lines {
		if !strings.Contains(line.Message, " watcher.cpp") && !strings.Contains(line.Message, " distributed.cpp") {
			t.Fatalf("non-error line %q", line.Message)
		}
	}
}

func TestElasticRejectsIndexEscape(t *testing.T) {
	e := &Elastic{Base: "http://127.0.0.1:9"}
	_, err := e.Search(context.Background(), SearchRequest{
		Source: Source{IndexPattern: "../secret", MessageField: "message", TimestampField: "@timestamp"},
		Limit:  1, From: time.Unix(0, 0), To: time.Unix(1, 0),
	})
	if err == nil {
		t.Fatal("accepted path escape")
	}
}

func TestSeedTailAndOrder(t *testing.T) {
	v := View{
		TimeZone: "UTC", MaxLines: 5000, DeviceScoped: true,
		Sources: []Source{
			{Index: 0, Label: "Munki", Color: "#ff9f0a", MessageField: "message", TimestampField: "@timestamp", KQL: `host.name: {{hostname}}`},
			{Index: 1, Label: "Falcon", Color: "#0a84ff", MessageField: "message", TimestampField: "@timestamp", KQL: `host.name: {{hostname}}`},
		},
	}
	to := time.Unix(1_700_000_000, 0).UTC()
	from := to.Add(-time.Hour)
	e := &Engine{Reader: Seed{}, Now: func() time.Time { return to }}
	page, err := e.Run(context.Background(), RunRequest{View: v, From: from, To: to, Limit: 30, Align: "end", Bind: &Bind{Hostname: "MBP-ENG-0101"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Lines) == 0 {
		t.Fatal("empty seed")
	}
	var prev time.Time
	for i, line := range page.Lines {
		if line.Host != "MBP-ENG-0101" {
			t.Fatalf("host %s", line.Host)
		}
		if i > 0 && line.Timestamp.Before(prev) {
			t.Fatal("out of order")
		}
		prev = line.Timestamp
	}
	e.Now = func() time.Time { return to.Add(2 * time.Minute) }
	tail, err := e.Run(context.Background(), RunRequest{View: v, Bind: &Bind{Hostname: "MBP-ENG-0101"}, Cursor: page.Cursor, Dir: "forward", Extend: true, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(tail.Lines) == 0 {
		t.Fatal("tail added nothing")
	}
	for _, line := range tail.Lines {
		if !line.Timestamp.After(page.Lines[len(page.Lines)-1].Timestamp) && !line.Timestamp.Equal(page.Lines[len(page.Lines)-1].Timestamp) {
			t.Fatalf("tail went backwards: %s then %s", page.Lines[len(page.Lines)-1].Timestamp, line.Timestamp)
		}
		if line.ID == page.Lines[len(page.Lines)-1].ID {
			t.Fatal("tail repeated the boundary line")
		}
	}
}
