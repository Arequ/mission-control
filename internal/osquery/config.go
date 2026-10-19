package osquery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/Arequ/mission-control/internal/config"
)

// BuildConfig renders the osquery TLS config for a device platform and returns
// a stable hash of that document. Built-in inventory queries fill any names the
// declarative config did not already define.
func BuildConfig(resources []config.Resource, platform string) (map[string]any, string) {
	schedule := map[string]any{}
	packs := map[string]any{}
	defined := map[string]bool{}

	for _, r := range resources {
		switch r.Kind {
		case config.KindOsqueryQuery:
			var spec config.OsqueryQuerySpec
			if err := decode(r.Spec, &spec); err != nil {
				continue
			}
			if !platformMatch(spec.Platform, platform) {
				continue
			}
			schedule[r.Metadata.Name] = queryObj(spec.Query, spec.Interval, spec.Snapshot, spec.Removed)
			defined[r.Metadata.Name] = true
		case config.KindOsqueryPack:
			var spec config.OsqueryPackSpec
			if err := decode(r.Spec, &spec); err != nil {
				continue
			}
			if !platformMatch(spec.Platform, platform) {
				continue
			}
			queries := map[string]any{}
			for _, q := range spec.Queries {
				if !platformMatch(q.Platform, platform) {
					continue
				}
				queries[q.Name] = queryObj(q.Query, q.Interval, q.Snapshot, q.Removed)
				defined[q.Name] = true
			}
			if len(queries) == 0 {
				continue
			}
			pack := map[string]any{"queries": queries}
			if spec.Platform != "" {
				pack["platform"] = spec.Platform
			}
			if len(spec.Discovery) > 0 {
				pack["discovery"] = spec.Discovery
			}
			packs[r.Metadata.Name] = pack
		case config.KindLabel:
			var spec config.LabelSpec
			if err := decode(r.Spec, &spec); err != nil {
				continue
			}
			if !platformMatch(spec.Platform, platform) {
				continue
			}
			key := "label_" + r.Metadata.Name
			snap := true
			schedule[key] = queryObj(spec.Query, spec.Interval, &snap, nil)
			defined[key] = true
		}
	}

	for name, query := range builtinQueries(platform) {
		if !defined[name] {
			schedule[name] = query
		}
	}

	cfg := map[string]any{
		"options": map[string]any{
			"pack_delimiter":      "/",
			"disable_distributed": false,
		},
		"schedule": schedule,
	}
	if len(packs) > 0 {
		cfg["packs"] = packs
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return cfg, ""
	}
	sum := sha256.Sum256(body)
	return cfg, hex.EncodeToString(sum[:])
}

// ExpectedHashes returns the config hash for each platform the server cares about.
func ExpectedHashes(resources []config.Resource) map[string]string {
	out := map[string]string{}
	for _, platform := range []string{"", "darwin", "windows", "linux"} {
		_, hash := BuildConfig(resources, platform)
		out[platform] = hash
	}
	return out
}

func builtinQueries(platform string) map[string]any {
	snap := true
	out := map[string]any{
		"system_info": queryObj("SELECT hostname, computer_name, uuid, hardware_serial, hardware_model, hardware_vendor, cpu_brand, cpu_physical_cores, physical_memory FROM system_info;", 3600, &snap, nil),
		"os_version":  queryObj("SELECT name, version, major, minor, build, platform FROM os_version;", 3600, &snap, nil),
		"users":       queryObj("SELECT uid, gid, username, description, directory, shell FROM users;", 3600, &snap, nil),
	}
	switch platform {
	case "windows":
		out["apps"] = queryObj("SELECT name, version, install_location AS path FROM programs;", 21600, &snap, nil)
	case "linux":
		out["apps"] = queryObj("SELECT name, version, '' AS path FROM deb_packages;", 21600, &snap, nil)
	default:
		out["apps"] = queryObj("SELECT name, path, bundle_identifier, bundle_short_version FROM apps;", 21600, &snap, nil)
	}
	return out
}

func queryObj(query string, interval int, snapshot, removed *bool) map[string]any {
	if interval < 1 {
		interval = 3600
	}
	q := map[string]any{
		"query":    strings.TrimSpace(query),
		"interval": interval,
	}
	if snapshot != nil {
		q["snapshot"] = *snapshot
	}
	if removed != nil {
		q["removed"] = *removed
	}
	return q
}

func platformMatch(want, have string) bool {
	if want == "" || have == "" {
		return true
	}
	if want == have {
		return true
	}
	if want == "posix" && (have == "darwin" || have == "linux") {
		return true
	}
	return false
}

func decode(spec map[string]any, dest any) error {
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dest)
}
