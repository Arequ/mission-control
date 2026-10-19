package logs

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Seed reads a deterministic log without Elasticsearch. Line i of a source is
// at a fixed offset from the Unix epoch, so pages, tails, and context agree.
type Seed struct{}

// Search implements Reader.
func (Seed) Search(_ context.Context, req SearchRequest) (Result, error) {
	hits := seedHits(req)
	return Memory{Hits: hits}.search(req)
}

func seedHits(req SearchRequest) []Hit {
	kind, ok := seedKind(req.Source.Label)
	if !ok {
		kind = seedSpec{interval: 19 * time.Second, file: req.Source.Label + ".log", line: genericLine}
	}
	if req.Limit <= 0 {
		return nil
	}
	host := req.Host
	if host == "" {
		host = "localhost"
	}
	epoch := time.Unix(0, 0).UTC()
	start := firstIndex(req.From, kind.interval)
	end := lastIndex(req.To, kind.interval)
	if req.After != nil {
		after := firstIndex(req.After.Time, kind.interval)
		ts := epoch.Add(time.Duration(after) * kind.interval)
		if ts.Equal(req.After.Time) && !req.After.Before(seedKey(req, after, ts)) {
			after++
		}
		if after > start {
			start = after
		}
	}
	if req.Before != nil {
		before := lastIndex(req.Before.Time.Add(time.Nanosecond), kind.interval)
		ts := epoch.Add(time.Duration(before) * kind.interval)
		if before >= 0 && ts.Equal(req.Before.Time) && !seedKey(req, before, ts).Before(*req.Before) {
			before--
		}
		if before < end {
			end = before
		}
	}
	if end < start {
		return nil
	}
	onlyErrors := strings.Contains(req.KQL, `log.level: "error"`) || strings.Contains(req.KQL, `log.level:"error"`)
	if onlyErrors && req.Source.Label != "osquery" {
		return nil
	}
	match := func(i int64) bool {
		return !onlyErrors || seedErrorLine(req.Source.Label, i)
	}
	// Walk only as far as the page needs. Counting every index back to the
	// epoch makes a wide context read scan hundreds of millions of steps.
	keep := int64(req.Limit + 4)
	var idxs []int64
	if req.Desc || req.Before != nil {
		for i := end; i >= start && int64(len(idxs)) < keep; i-- {
			if match(i) {
				idxs = append(idxs, i)
			}
		}
		for l, r := 0, len(idxs)-1; l < r; l, r = l+1, r-1 {
			idxs[l], idxs[r] = idxs[r], idxs[l]
		}
	} else {
		for i := start; i <= end && int64(len(idxs)) < keep; i++ {
			if match(i) {
				idxs = append(idxs, i)
			}
		}
	}
	if len(idxs) == 0 {
		return nil
	}
	out := make([]Hit, 0, len(idxs))
	for _, i := range idxs {
		ts := time.Unix(0, 0).UTC().Add(time.Duration(i) * kind.interval)
		out = append(out, Hit{
			Source: req.Source.Index,
			Time:   ts,
			Seq:    i,
			Tie:    fmt.Sprintf("%s#%d", req.Source.Label, i),
			File:   kind.file,
			Host:   host,
			Msg:    kind.line(i, host, ts),
		})
	}
	return out
}

func seedErrorLine(label string, i int64) bool {
	if label != "osquery" {
		return false
	}
	return i%5 == 0 || i%5 == 3
}

func seedKey(req SearchRequest, i int64, ts time.Time) Key {
	return Key{Time: ts, Source: req.Source.Index, Seq: i, Tie: fmt.Sprintf("%s#%d", req.Source.Label, i)}
}

func firstIndex(from time.Time, iv time.Duration) int64 {
	epoch := time.Unix(0, 0).UTC()
	if !from.After(epoch) {
		return 0
	}
	i := int64(from.Sub(epoch) / iv)
	if epoch.Add(time.Duration(i) * iv).Before(from) {
		i++
	}
	return i
}

func lastIndex(to time.Time, iv time.Duration) int64 {
	epoch := time.Unix(0, 0).UTC()
	if !to.After(epoch) {
		return -1
	}
	i := int64(to.Sub(epoch) / iv)
	if !epoch.Add(time.Duration(i) * iv).Before(to) {
		i--
	}
	return i
}

type seedSpec struct {
	interval time.Duration
	file     string
	line     func(i int64, host string, t time.Time) string
}

func seedKind(label string) (seedSpec, bool) {
	switch label {
	case "Munki":
		return seedSpec{17 * time.Second, "/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log", munkiLine}, true
	case "AutoPkg":
		return seedSpec{23 * time.Second, "/Library/AutoPkg/Logs/autopkg.log", autopkgLine}, true
	case "osquery":
		return seedSpec{13 * time.Second, "/var/log/osquery/osqueryd.results.log", osqueryLine}, true
	case "Falcon":
		return seedSpec{11 * time.Second, "/Library/CS/Logs/falconctl.log", falconLine}, true
	default:
		return seedSpec{}, false
	}
}

func stamp(t time.Time) string {
	return t.UTC().Format("Jan 02 15:04:05")
}

func munkiLine(i int64, host string, t time.Time) string {
	pid := 4800 + int(i%90)
	switch i % 8 {
	case 0:
		return fmt.Sprintf("%s Managed Software Update[%d]: ### Beginning managed software check on %s ###", stamp(t), pid, host)
	case 1:
		return fmt.Sprintf("%s Managed Software Update[%d]: Checking Apple software update catalog", stamp(t), pid)
	case 2:
		return fmt.Sprintf("%s Managed Software Update[%d]: Downloading Firefox-132.0.1.dmg", stamp(t), pid)
	case 3:
		return fmt.Sprintf("%s Managed Software Update[%d]: Installing Firefox 132.0.1 from testing", stamp(t), pid)
	case 4:
		return fmt.Sprintf("%s Managed Software Update[%d]: The following items were installed: Firefox", stamp(t), pid)
	case 5:
		return fmt.Sprintf("%s Managed Software Update[%d]: No changes to optional installs for %s", stamp(t), pid, host)
	case 6:
		return fmt.Sprintf("%s Managed Software Update[%d]: WARNING: Could not retrieve icon for Slack", stamp(t), pid)
	default:
		return fmt.Sprintf("%s Managed Software Update[%d]: ### End managed software check ###", stamp(t), pid)
	}
}

func autopkgLine(i int64, host string, t time.Time) string {
	switch i % 6 {
	case 0:
		return fmt.Sprintf("%s autopkg: Processing local.munki.Firefox...", stamp(t))
	case 1:
		return fmt.Sprintf("%s autopkg: Downloading https://download.mozilla.org/firefox/releases/132.0.1/mac/en-US/Firefox.dmg", stamp(t))
	case 2:
		return fmt.Sprintf("%s autopkg: Receipt written for Firefox version 132.0.1", stamp(t))
	case 3:
		return fmt.Sprintf("%s autopkg: Processing local.munki.Slack...", stamp(t))
	case 4:
		return fmt.Sprintf("%s autopkg: WARNING: trust info for Slack does not match the parent recipe", stamp(t))
	default:
		return fmt.Sprintf("%s autopkg: Done. Runner mini-1 reported %s", stamp(t), host)
	}
}

func osqueryLine(i int64, host string, t time.Time) string {
	clock := t.UTC().Format("0102 15:04:05.000000")
	switch i % 5 {
	case 0:
		return fmt.Sprintf("E%s 2214 watcher.cpp:341] Extension binary died on %s", clock, host)
	case 1:
		return fmt.Sprintf("I%s 2214 config.cpp:88] Refreshing configuration from Mission Control", clock)
	case 2:
		return fmt.Sprintf("W%s 2214 tls.cpp:119] TLS handshake retry host=%s", clock, host)
	case 3:
		return fmt.Sprintf("E%s 2214 distributed.cpp:204] Query mc_label_apple_silicon failed: no such table", clock)
	default:
		return fmt.Sprintf("I%s 2214 scheduler.cpp:512] Snapshot query pack/endpoint completed on %s", clock, host)
	}
}

func falconLine(i int64, host string, t time.Time) string {
	switch i % 6 {
	case 0:
		return fmt.Sprintf("%s FalconSensor[318]: heartbeat host=%s cid=acme aid=4f1c8e2a", stamp(t), host)
	case 1:
		return fmt.Sprintf("%s FalconSensor[318]: Sensor operational, version 7.18.19003", stamp(t))
	case 2:
		return fmt.Sprintf("%s FalconSensor[318]: ProcessRollup2 user=ava.thompson process=curl cmdline=\"curl -fsSL https://get.example-tool.dev/install.sh\"", stamp(t))
	case 3:
		return fmt.Sprintf("%s FalconSensor[318]: ProcessRollup2 user=ava.thompson process=python3 cmdline=\"python3 -m pip install --user requests\"", stamp(t))
	case 4:
		return fmt.Sprintf("%s FalconSensor[318]: DnsRequest host=%s domain=download.mozilla.org", stamp(t), host)
	default:
		return fmt.Sprintf("%s FalconSensor[318]: Cloud request succeeded, trace=mc-%d", stamp(t), i%1000)
	}
}

func genericLine(i int64, host string, t time.Time) string {
	return fmt.Sprintf("%s log[%d]: line on %s", stamp(t), i, host)
}
