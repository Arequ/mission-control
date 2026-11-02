package coverage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Observation is one device as a connector last saw it.
// Fields holds normalized comparison values (hostname, os_version, serial,
// primary_user, ip_address, agent_version). Keys used for matching are also
// copied onto Keys.
type Observation struct {
	NativeID     string
	Keys         Keys
	OSVersion    string
	IPAddress    string
	AgentVersion string
	LastSeen     time.Time
	Fields       map[string]string
}

// Config is the connector settings a poll needs. Secrets are in memory for the
// call and must not be logged.
type Config struct {
	Source        string
	Mode          string
	BaseURL       string
	ClientID      string
	ClientSecret  string
	APIToken      string
	ElasticURL    string
	ElasticAPIKey string
	IndexPattern  string
	Query         string
	QueryLanguage string
	TimeField     string
	TimeZone      string
	FieldMap      map[string]string
	Lookback      time.Duration
	Now           time.Time
}

// Poller fetches the latest device records for one ingestion mode.
type Poller interface {
	Poll(ctx context.Context, cfg Config, hc *http.Client) ([]Observation, error)
}

// PollerFor selects the implementation for a source and mode.
// Rapid7, Netskope, Proofpoint, and BlastShield use Elastic in the example
// stack. Their API pollers are stubs with a documented placeholder response,
// not the vendor APIs.
func PollerFor(source, mode string) (Poller, error) {
	switch mode {
	case "elastic":
		return Elastic{}, nil
	case "native":
		return nil, fmt.Errorf("%s is projected inside Mission Control", source)
	case "api":
		switch source {
		case "crowdstrike":
			return Falcon{}, nil
		case "kolide":
			return Kolide{}, nil
		case "rapid7", "netskope", "proofpoint", "blastshield":
			return APIStub{Source: source}, nil
		default:
			return nil, fmt.Errorf("no API connector for %s", source)
		}
	default:
		return nil, fmt.Errorf("unknown connector mode %q", mode)
	}
}

func (o Observation) NormalizedFields() map[string]string {
	out := map[string]string{}
	for k, v := range o.Fields {
		if strings.TrimSpace(v) != "" {
			out[k] = strings.TrimSpace(v)
		}
	}
	set := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			out[k] = strings.TrimSpace(v)
		}
	}
	set("serial", o.Keys.Serial)
	set("hardware_uuid", o.Keys.HardwareUUID)
	set("mac", o.Keys.MAC)
	set("hostname", o.Keys.Hostname)
	set("primary_user", o.Keys.PrimaryUser)
	set("os_version", o.OSVersion)
	set("ip_address", o.IPAddress)
	set("agent_version", o.AgentVersion)
	return out
}

func doJSON(ctx context.Context, hc *http.Client, req *http.Request) ([]byte, int, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, 0, err
		}
	}
	var last []byte
	var status int
	for attempt := 0; attempt < 5; attempt++ {
		call := req.Clone(ctx)
		if body != nil {
			call.Body = io.NopCloser(bytes.NewReader(body))
			call.ContentLength = int64(len(body))
		}
		res, err := hc.Do(call)
		if err != nil {
			return nil, 0, err
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		_ = res.Body.Close()
		if err != nil {
			return nil, res.StatusCode, err
		}
		last, status = b, res.StatusCode
		if res.StatusCode != http.StatusTooManyRequests && res.StatusCode != http.StatusServiceUnavailable {
			return b, res.StatusCode, nil
		}
		wait := time.Duration(attempt+1) * 200 * time.Millisecond
		if n, err := strconv.Atoi(strings.TrimSpace(res.Header.Get("Retry-After"))); err == nil && n >= 0 {
			wait = time.Duration(n) * time.Second
		}
		if wait > 5*time.Second {
			wait = 5 * time.Second
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return b, res.StatusCode, ctx.Err()
		case <-timer.C:
		}
	}
	return last, status, nil
}

func statusError(op string, status int) error {
	return fmt.Errorf("%s: HTTP %d", op, status)
}

func trimURL(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}
