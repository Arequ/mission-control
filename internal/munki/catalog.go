// Package munki builds Munki catalogs and pkginfo from AutoPkg output.
package munki

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"howett.net/plist"
)

const emptyCatalog = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
</array>
</plist>
`

// ParsePkginfo decodes a plist or JSON pkginfo into a normalized map.
func ParsePkginfo(data []byte) (map[string]any, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty pkginfo")
	}
	var raw any
	if data[0] == '{' {
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("pkginfo json: %w", err)
		}
	} else {
		if _, err := plist.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("pkginfo plist: %w", err)
		}
	}
	m, ok := normalize(raw).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("pkginfo must be a dictionary")
	}
	if str(m["name"]) == "" {
		return nil, fmt.Errorf("pkginfo missing name")
	}
	if str(m["version"]) == "" {
		return nil, fmt.Errorf("pkginfo missing version")
	}
	return m, nil
}

// ApplyArtifact fills hash, size, location, and catalogs on a pkginfo dict.
func ApplyArtifact(info map[string]any, filename string, pkg []byte, catalog string) {
	sum := sha256.Sum256(pkg)
	info["installer_item_location"] = filename
	info["installer_item_hash"] = hex.EncodeToString(sum[:])
	// makepkginfo stores floor(bytes/1024). A file under 1 KiB is size 0.
	info["installer_item_size"] = int64(len(pkg)) / 1024
	info["catalogs"] = []any{catalog}
}

// MaxSoakDays is the largest soak that can be added to a timestamp without overflowing time.Duration.
const MaxSoakDays = 3660

// SoakDuration converts soak days into an exact multiple of 24 hours.
// Values outside 0..MaxSoakDays are rejected so a huge soak cannot overflow into an immediate promotion.
func SoakDuration(soakDays int) (time.Duration, bool) {
	if soakDays < 0 || soakDays > MaxSoakDays {
		return 0, false
	}
	return time.Duration(soakDays) * 24 * time.Hour, true
}

// MarshalPkginfo encodes pkginfo as JSON for storage.
func MarshalPkginfo(info map[string]any) ([]byte, error) {
	return json.Marshal(info)
}

// BuildCatalog renders a Munki catalog plist from pkginfo JSON objects.
func BuildCatalog(pkginfos [][]byte) ([]byte, error) {
	items := make([]any, 0, len(pkginfos))
	for _, raw := range pkginfos {
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("catalog item: %w", err)
		}
		norm := normalize(v)
		if m, ok := norm.(map[string]any); ok {
			stripCatalogMeta(m)
		}
		items = append(items, norm)
	}
	if len(items) == 0 {
		return []byte(emptyCatalog), nil
	}
	out, err := plist.MarshalIndent(items, plist.XMLFormat, "\t")
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ParseCatalog returns the array of dictionaries inside a catalog plist.
func ParseCatalog(data []byte) ([]map[string]any, error) {
	var raw any
	if _, err := plist.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("catalog is not an array")
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("catalog item is not a dictionary")
		}
		out = append(out, m)
	}
	return out, nil
}

// SoakDue reports whether a package has finished soaking.
// A manual hold blocks promotion. A zero soak is due immediately.
func SoakDue(now, soakStarted time.Time, soakDays int, manualHold bool) bool {
	if manualHold {
		return false
	}
	d, ok := SoakDuration(soakDays)
	if !ok {
		return false
	}
	deadline := soakStarted.UTC().Add(d)
	return !now.UTC().Before(deadline)
}

// ForCatalog returns pkginfo JSON for one catalog membership.
// notes and underscore keys are removed, matching makecatalogs, and catalogs is the catalog the row belongs to.
func ForCatalog(raw []byte, catalog string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("catalog item: %w", err)
	}
	m, ok := normalize(v).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("catalog item is not a dictionary")
	}
	stripCatalogMeta(m)
	if catalog != "" {
		m["catalogs"] = []any{catalog}
	}
	if str(m["name"]) == "" || str(m["version"]) == "" {
		return nil, fmt.Errorf("pkginfo missing name or version")
	}
	return json.Marshal(m)
}

func stripCatalogMeta(m map[string]any) {
	delete(m, "notes")
	for k := range m {
		if strings.HasPrefix(k, "_") {
			delete(m, k)
		}
	}
}

// ManifestPlist renders a Munki manifest.
func ManifestPlist(catalogs, included, managed, optional, uninstalls []string) ([]byte, error) {
	dict := map[string]any{
		"catalogs":           stringSlice(catalogs),
		"included_manifests": stringSlice(included),
		"managed_installs":   stringSlice(managed),
		"optional_installs":  stringSlice(optional),
		"managed_uninstalls": stringSlice(uninstalls),
	}
	return plist.MarshalIndent(dict, plist.XMLFormat, "\t")
}

func stringSlice(in []string) []any {
	if in == nil {
		in = []string{}
	}
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			t[k] = normalize(vv)
		}
		return t
	case []any:
		for i := range t {
			t[i] = normalize(t[i])
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case float64:
		if !math.IsInf(t, 0) && !math.IsNaN(t) && t == math.Trunc(t) && t <= math.MaxInt64 && t >= math.MinInt64 {
			return int64(t)
		}
		return t
	case float32:
		return normalize(float64(t))
	case uint64:
		return int64(t)
	default:
		return v
	}
}
