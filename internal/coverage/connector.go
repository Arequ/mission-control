package coverage

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	Source         string
	Mode           string
	BaseURL        string
	ClientID       string
	ClientSecret   string
	APIToken       string
	ElasticURL     string
	ElasticAPIKey  string
	IndexPattern   string
	Query          string
	QueryLanguage  string
	TimeField      string
	FieldMap       map[string]string
	Lookback       time.Duration
	Now            time.Time
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
	req = req.WithContext(ctx)
	res, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, res.StatusCode, err
	}
	return b, res.StatusCode, nil
}

func statusError(op string, status int) error {
	return fmt.Errorf("%s: HTTP %d", op, status)
}

func trimURL(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
