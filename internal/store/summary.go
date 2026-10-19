package store

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// OnlineWindow is how recently a device must have been seen to count as online.
const OnlineWindow = 30 * time.Minute

// Summarize builds dashboard counts from a device list and app aggregates.
// expected maps a platform (or "" as the fallback) to the config hash agents
// should be running.
func Summarize(devices []Device, apps []AppCount, expected map[string]string, now time.Time) FleetSummary {
	summary := FleetSummary{
		Devices:     len(devices),
		Platforms:   []NamedCount{},
		OSVersions:  []NamedCount{},
		Models:      []NamedCount{},
		TopApps:     apps,
		Recent:      []Device{},
		GeneratedAt: now,
	}
	if summary.TopApps == nil {
		summary.TopApps = []AppCount{}
	}
	platforms := map[string]int{}
	versions := map[string]int{}
	models := map[string]int{}
	for _, d := range devices {
		if d.LastSeenAt != nil && now.Sub(d.LastSeenAt.UTC()) <= OnlineWindow {
			summary.Online++
		}
		want := expected[d.Platform]
		if want == "" {
			want = expected[""]
		}
		if want != "" && d.ConfigHash != want {
			summary.ConfigDrift++
		}
		platforms[blank(d.Platform, "unknown")]++
		versions[blank(strings.TrimSpace(strings.TrimSpace(d.OSName+" "+d.OSVersion)), "unknown")]++
		models[blank(d.HardwareModel, "unknown")]++
	}
	summary.Offline = summary.Devices - summary.Online
	summary.Platforms = counts(platforms)
	summary.OSVersions = counts(versions)
	summary.Models = counts(models)
	if len(summary.Models) > 6 {
		summary.Models = summary.Models[:6]
	}
	recent := append([]Device{}, devices...)
	sort.Slice(recent, func(i, j int) bool {
		return recent[i].EnrolledAt.After(recent[j].EnrolledAt)
	})
	if len(recent) > 6 {
		recent = recent[:6]
	}
	for i := range recent {
		recent[i].Inventory = nil
		recent[i].NodeKeyHash = ""
		if recent[i].Labels == nil {
			recent[i].Labels = []string{}
		}
	}
	summary.Recent = recent
	return summary
}

func blank(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func counts(m map[string]int) []NamedCount {
	out := make([]NamedCount, 0, len(m))
	for name, n := range m {
		out = append(out, NamedCount{Name: name, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// MergeIdentity copies non-empty hardware and OS fields onto dst.
func MergeIdentity(dst *Device, patch Device) {
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&dst.HostIdentifier, patch.HostIdentifier)
	set(&dst.Hostname, patch.Hostname)
	set(&dst.ComputerName, patch.ComputerName)
	set(&dst.UUID, patch.UUID)
	set(&dst.HardwareSerial, patch.HardwareSerial)
	set(&dst.HardwareModel, patch.HardwareModel)
	set(&dst.HardwareVendor, patch.HardwareVendor)
	set(&dst.CPUBrand, patch.CPUBrand)
	set(&dst.Platform, patch.Platform)
	set(&dst.OSName, patch.OSName)
	set(&dst.OSVersion, patch.OSVersion)
	set(&dst.OSBuild, patch.OSBuild)
	set(&dst.OSQueryVersion, patch.OSQueryVersion)
	set(&dst.PrimaryUser, patch.PrimaryUser)
	if patch.CPUPhysicalCores != 0 {
		dst.CPUPhysicalCores = patch.CPUPhysicalCores
	}
	if patch.PhysicalMemory != 0 {
		dst.PhysicalMemory = patch.PhysicalMemory
	}
}

// ApplyLabel adds or removes one label, returning a sorted unique list.
func ApplyLabel(labels []string, upd LabelUpdate) []string {
	next := make([]string, 0, len(labels)+1)
	seen := false
	for _, label := range labels {
		if label == upd.Name {
			seen = true
			if upd.Member {
				next = append(next, label)
			}
			continue
		}
		if label != "" {
			next = append(next, label)
		}
	}
	if upd.Member && !seen {
		next = append(next, upd.Name)
	}
	sort.Strings(next)
	return next
}

func cloneDevice(d Device) Device {
	out := d
	out.NodeKeyHash = d.NodeKeyHash
	if d.Labels != nil {
		out.Labels = append([]string{}, d.Labels...)
	} else {
		out.Labels = []string{}
	}
	if d.Inventory != nil {
		out.Inventory = make(map[string]json.RawMessage, len(d.Inventory))
		for k, v := range d.Inventory {
			out.Inventory[k] = append(json.RawMessage(nil), v...)
		}
	}
	if d.LastSeenAt != nil {
		t := d.LastSeenAt.UTC()
		out.LastSeenAt = &t
	}
	return out
}

func publicDevice(d Device) Device {
	out := cloneDevice(d)
	out.NodeKeyHash = ""
	return out
}
