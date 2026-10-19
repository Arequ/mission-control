package logs

import (
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestContextReachesPastThirtyDays(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	anchor := old.Add(40 * 24 * time.Hour)
	hits := []Hit{
		{Source: 0, Time: old, Tie: "old", Msg: "old-line"},
		{Source: 0, Time: anchor, Tie: "now", Msg: "now-line"},
	}
	e := &Engine{Reader: Memory{Hits: hits}}
	id := encodeLine(hits[1])
	out, err := e.Context(context.Background(), view2(), nil, id, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stringsJoin(msgs(out.Lines)) != "old-line now-line" {
		t.Fatalf("context = %v", msgs(out.Lines))
	}
}

func TestPageLimitIsCapped(t *testing.T) {
	hits := make([]Hit, 0, 5000)
	for i := 0; i < 5000; i++ {
		hits = append(hits, hit(0, i, 0, "m"))
	}
	// One source is enough; view2's second source just returns nothing.
	v := view2()
	v.MaxLines = MaxViewLines
	page, err := engine(hits).Run(context.Background(), RunRequest{
		View: v, From: time.Unix(0, 0), To: time.Unix(10_000, 0), Limit: 9000, Align: "start",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Lines) != MaxPage {
		t.Fatalf("page %d, want the %d cap", len(page.Lines), MaxPage)
	}
	if !page.HasMoreAfter {
		t.Fatal("cap hid the rest of the source")
	}
}

func TestPlaceholderCannotBreakOut(t *testing.T) {
	nasty := []string{
		`a" or host.name:* or host.name:"b`,
		`foo\`,
		`host-*`,
		`x AND y OR not host.name: *`,
		"line1\nline2",
		`mbp-2`,
	}
	for _, value := range nasty {
		got, err := Substitute(`host.name: {{hostname}}`, Bind{Hostname: value})
		if strings.Contains(value, "\n") {
			if err == nil {
				t.Fatalf("control character accepted: %q", got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("substitute %q: %v", value, err)
		}
		q, err := Compile(got, "message")
		if err != nil {
			t.Fatalf("compile %q (%s): %v", value, got, err)
		}
		raw, _ := json.Marshal(q)
		if strings.Contains(string(raw), "query_string") || strings.Contains(string(raw), "wildcard") {
			t.Fatalf("%q compiled to %s", value, raw)
		}
		if !strings.Contains(string(raw), "match_phrase") && !strings.Contains(string(raw), `"term"`) {
			t.Fatalf("%q compiled to %s", value, raw)
		}
	}
}

func TestDeviceScopeRejectsUnanchoredBranches(t *testing.T) {
	bad := []string{
		`* or host.name: {{hostname}}`,
		`not host.name: {{hostname}}`,
		`host.name: {{hostname}} or message: "hello"`,
		`message: "hello"`,
	}
	for _, kql := range bad {
		if err := Anchored(kql); err == nil {
			t.Fatalf("accepted %s", kql)
		}
	}
	if err := Anchored(`host.name: {{hostname}} or host.serial: {{serial}}`); err != nil {
		t.Fatal(err)
	}
	if err := requireBindValues(`host.name: {{hostname}}`, Bind{}); err == nil {
		t.Fatal("empty hostname accepted")
	}
}

func TestKQLFuzzStaysInSubset(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	alphabet := []rune("abcXYZ019 _-.@*?:()\"\\andorNOT")
	for i := 0; i < 300; i++ {
		n := r.Intn(80)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteRune(alphabet[r.Intn(len(alphabet))])
		}
		q := b.String()
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("panic on %q: %v", q, rec)
				}
			}()
			out, err := Compile(q, "message")
			if err != nil {
				return
			}
			raw, merr := json.Marshal(out)
			if merr != nil {
				t.Fatal(merr)
			}
			if strings.Contains(string(raw), "query_string") || strings.Contains(string(raw), "script") {
				t.Fatalf("%q -> %s", q, raw)
			}
		}()
		nested := strings.Repeat("(", 40) + "message: hi" + strings.Repeat(")", 40)
		if _, err := Compile(nested, "message"); err == nil {
			t.Fatal("depth cap not enforced")
		}
	}
}

func TestIndexPatternNeedsALiteralPrefix(t *testing.T) {
	for _, pattern := range []string{"*", "*,secret", "logs-a,logs-b", "..", "/*", "?", ".kibana"} {
		if err := ValidIndexPattern(pattern); err == nil && pattern != ".kibana" {
			t.Fatalf("accepted %s", pattern)
		}
	}
	if err := ValidIndexPattern(".kibana"); err != nil {
		t.Fatal(err)
	}
	if err := ValidIndexPattern("logs-munki.install-*"); err != nil {
		t.Fatal(err)
	}
}

func TestElasticURLRejectsMetadataAndRedirects(t *testing.T) {
	if err := ValidateElasticURL("http://169.254.169.254/latest/meta-data"); err == nil {
		t.Fatal("link-local url accepted")
	}
	if err := ValidateElasticURL("http://metadata.google.internal/"); err == nil {
		t.Fatal("metadata host accepted")
	}
	if err := ValidateElasticURL("https://user:pass@elastic.example"); err == nil {
		t.Fatal("userinfo accepted")
	}
	if err := ValidateElasticURL("http://10.0.0.8:9200"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_pit") || strings.Contains(r.URL.Path, "/_search") {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "key was secret-api-key")
	}))
	defer srv.Close()
	e := &Elastic{Base: srv.URL, APIKey: "secret-api-key", HTTP: SafeClient()}
	_, err := e.Search(context.Background(), SearchRequest{
		Source:   Source{Index: 0, IndexPattern: "logs-*", MessageField: "message", TimestampField: "@timestamp"},
		Location: time.UTC, From: time.Unix(0, 0), To: time.Unix(10, 0), Limit: 1,
	})
	if err == nil {
		t.Fatal("redirect was followed")
	}
	if strings.Contains(err.Error(), "secret-api-key") || strings.Contains(err.Error(), "169.254.169.254") {
		t.Fatalf("error leaked target or key: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/", nil)
	if _, err := SafeClient().Do(req); err == nil {
		t.Fatal("dialed link-local")
	}
}

func TestElasticErrorRedactsAPIKey(t *testing.T) {
	const key = "super-secret-elastic-key"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "refused "+key)
	}))
	defer srv.Close()
	e := &Elastic{Base: srv.URL, APIKey: key, HTTP: srv.Client()}
	_, err := e.Search(context.Background(), SearchRequest{
		Source:   Source{Index: 0, IndexPattern: "logs-*", MessageField: "message", TimestampField: "@timestamp"},
		Location: time.UTC, From: time.Unix(0, 0), To: time.Unix(10, 0), Limit: 1,
	})
	if err == nil || strings.Contains(err.Error(), key) {
		t.Fatalf("key leaked: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("error = %v", err)
	}
}
