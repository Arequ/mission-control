package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ResultEvent is one result row eligible for the log sink.
type ResultEvent struct {
	DeviceID   string            `json:"device_id"`
	Hostname   string            `json:"hostname,omitempty"`
	QueryName  string            `json:"query_name"`
	Action     string            `json:"action"`
	Columns    map[string]string `json:"columns"`
	UnixTime   int64             `json:"unix_time"`
	ReceivedAt time.Time         `json:"received_at"`
}

// Forwarder ships result logs to an external sink. Postgres remains the source of record.
type Forwarder interface {
	Forward(ctx context.Context, events []ResultEvent) error
}

// NopForwarder discards events. It is the default when Elastic is not configured.
type NopForwarder struct{}

func (NopForwarder) Forward(context.Context, []ResultEvent) error { return nil }

// ElasticForwarder posts an Elasticsearch _bulk request.
// MC_ELASTIC_URL empty means the server uses NopForwarder instead.
type ElasticForwarder struct {
	URL    string
	Index  string
	APIKey string
	HTTP   *http.Client
}

// Forward sends events as NDJSON bulk actions. A non-2xx response is an error.
// The API key is not included in the error string.
func (e ElasticForwarder) Forward(ctx context.Context, events []ResultEvent) error {
	if len(events) == 0 || strings.TrimSpace(e.URL) == "" {
		return nil
	}
	index := e.Index
	if index == "" {
		index = "osquery-results"
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, ev := range events {
		if err := enc.Encode(map[string]any{"index": map[string]string{"_index": index}}); err != nil {
			return err
		}
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(e.URL, "/")+"/_bulk", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if key := strings.TrimSpace(e.APIKey); key != "" {
		if strings.HasPrefix(strings.ToLower(key), "apikey ") {
			req.Header.Set("Authorization", key)
		} else {
			req.Header.Set("Authorization", "ApiKey "+key)
		}
	}
	hc := e.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("elastic bulk: %s", e.redact(err.Error()))
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode >= 300 {
		return fmt.Errorf("elastic bulk %d: %s", res.StatusCode, e.redact(strings.TrimSpace(string(body))))
	}
	return nil
}

func (e ElasticForwarder) redact(msg string) string {
	if key := strings.TrimSpace(e.APIKey); key != "" {
		msg = strings.ReplaceAll(msg, key, "[redacted]")
		bare := strings.TrimPrefix(strings.TrimPrefix(key, "ApiKey "), "apikey ")
		if bare != "" && bare != key {
			msg = strings.ReplaceAll(msg, bare, "[redacted]")
		}
	}
	raw := strings.TrimSpace(e.URL)
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		if name := u.User.Username(); name != "" {
			msg = strings.ReplaceAll(msg, name, "[redacted]")
		}
		if pw, ok := u.User.Password(); ok && pw != "" {
			msg = strings.ReplaceAll(msg, pw, "[redacted]")
		}
	}
	return msg
}
