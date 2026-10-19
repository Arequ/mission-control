package osquery

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/store"
)

// IngestResult stores one osquery result log line and, for known inventory
// queries, updates the device record.
func IngestResult(ctx context.Context, st store.Store, deviceID string, item map[string]any) error {
	name := asString(item["name"])
	if name == "" {
		name = "unknown"
	}
	collected := time.Now().UTC()
	if unix, ok := asInt64(item["unixTime"]); ok && unix > 0 {
		collected = time.Unix(unix, 0).UTC()
	}
	result := store.QueryResult{Name: name, CollectedAt: collected}
	if snap, ok := item["snapshot"]; ok {
		raw, err := json.Marshal(snap)
		if err != nil {
			return err
		}
		result.Snapshot = raw
	}
	if diff := asMap(item["diffResults"]); diff != nil {
		if added, ok := diff["added"]; ok {
			raw, err := json.Marshal(added)
			if err != nil {
				return err
			}
			result.Added = raw
		}
		if removed, ok := diff["removed"]; ok {
			raw, err := json.Marshal(removed)
			if err != nil {
				return err
			}
			result.Removed = raw
		}
	}
	if err := st.AddResult(ctx, deviceID, result); err != nil {
		return err
	}

	base := BaseName(name)
	var rows []map[string]any
	_, hasSnapshot := item["snapshot"]
	if hasSnapshot {
		rows = asRows(item["snapshot"])
	}

	patch := store.Device{}
	var apps *[]store.App
	var labels []store.LabelUpdate
	switch base {
	case "system_info":
		if len(rows) > 0 {
			patch = patchFromSystem(rows[0])
		}
	case "os_version":
		if len(rows) > 0 {
			patch = patchFromOS(rows[0])
		}
	case "users":
		if user := pickUser(rows); user != "" {
			patch.PrimaryUser = user
		}
	case "apps":
		if hasSnapshot {
			list := appsFrom(rows)
			apps = &list
		}
	}
	if strings.HasPrefix(base, "label_") {
		label := strings.TrimPrefix(base, "label_")
		if hasSnapshot {
			labels = append(labels, store.LabelUpdate{Name: label, Member: len(rows) > 0})
		} else if diff := asMap(item["diffResults"]); diff != nil {
			added := asRows(diff["added"])
			removed := asRows(diff["removed"])
			if len(added) > 0 {
				labels = append(labels, store.LabelUpdate{Name: label, Member: true})
			} else if len(removed) > 0 {
				labels = append(labels, store.LabelUpdate{Name: label, Member: false})
			}
		}
	}

	snapshots := map[string]json.RawMessage{}
	if result.Snapshot != nil {
		snapshots[base] = result.Snapshot
	}
	if !identityChanged(patch) && apps == nil && len(labels) == 0 && len(snapshots) == 0 {
		return nil
	}
	return st.ApplyInventory(ctx, deviceID, patch, snapshots, apps, labels)
}

func identityChanged(d store.Device) bool {
	return d.Hostname != "" || d.ComputerName != "" || d.UUID != "" || d.HardwareSerial != "" ||
		d.HardwareModel != "" || d.HardwareVendor != "" || d.CPUBrand != "" || d.CPUPhysicalCores != 0 ||
		d.PhysicalMemory != 0 || d.Platform != "" || d.OSName != "" || d.OSVersion != "" ||
		d.OSBuild != "" || d.OSQueryVersion != "" || d.PrimaryUser != ""
}

func patchFromSystem(row map[string]any) store.Device {
	return store.Device{
		Hostname:         asString(row["hostname"]),
		ComputerName:     asString(row["computer_name"]),
		UUID:             asString(row["uuid"]),
		HardwareSerial:   asString(row["hardware_serial"]),
		HardwareModel:    asString(row["hardware_model"]),
		HardwareVendor:   asString(row["hardware_vendor"]),
		CPUBrand:         asString(row["cpu_brand"]),
		CPUPhysicalCores: asInt(row["cpu_physical_cores"]),
		PhysicalMemory:   func() int64 { n, _ := asInt64(row["physical_memory"]); return n }(),
	}
}

func patchFromOS(row map[string]any) store.Device {
	return store.Device{
		OSName:    asString(row["name"]),
		OSVersion: asString(row["version"]),
		OSBuild:   asString(row["build"]),
		Platform:  asString(row["platform"]),
	}
}

func pickUser(rows []map[string]any) string {
	best := ""
	bestUID := int(^uint(0) >> 1)
	for _, row := range rows {
		name := firstNonEmpty(asString(row["username"]), asString(row["user"]))
		if name == "" || name == "root" || strings.HasPrefix(name, "_") {
			continue
		}
		uid := asInt(row["uid"])
		if uid == 0 {
			if best == "" {
				best = name
			}
			continue
		}
		if uid >= 500 && uid < bestUID {
			bestUID = uid
			best = name
		}
	}
	return best
}

func appsFrom(rows []map[string]any) []store.App {
	var apps []store.App
	seen := map[string]bool{}
	for _, row := range rows {
		name := firstNonEmpty(asString(row["name"]), asString(row["bundle_name"]))
		if name == "" {
			continue
		}
		app := store.App{
			Name:     name,
			BundleID: firstNonEmpty(asString(row["bundle_identifier"]), asString(row["bundle_id"])),
			Path:     firstNonEmpty(asString(row["path"]), asString(row["install_location"])),
			Version:  firstNonEmpty(asString(row["bundle_short_version"]), asString(row["bundle_version"]), asString(row["version"])),
		}
		key := app.Name + "\x00" + app.BundleID + "\x00" + app.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		apps = append(apps, app)
	}
	if apps == nil {
		apps = []store.App{}
	}
	return apps
}

// DeviceFromEnroll maps an enroll request onto a device.
func DeviceFromEnroll(hostIdentifier string, details map[string]any) store.Device {
	d := store.Device{HostIdentifier: hostIdentifier, Hostname: hostIdentifier}
	if sys := asMap(details["system_info"]); sys != nil {
		sysPatch := patchFromSystem(sys)
		d.Hostname = firstNonEmpty(sysPatch.Hostname, hostIdentifier)
		d.ComputerName = sysPatch.ComputerName
		d.UUID = sysPatch.UUID
		d.HardwareSerial = sysPatch.HardwareSerial
		d.HardwareModel = sysPatch.HardwareModel
		d.HardwareVendor = sysPatch.HardwareVendor
		d.CPUBrand = sysPatch.CPUBrand
		d.CPUPhysicalCores = sysPatch.CPUPhysicalCores
		d.PhysicalMemory = sysPatch.PhysicalMemory
	}
	if osv := asMap(details["os_version"]); osv != nil {
		osPatch := patchFromOS(osv)
		d.OSName = osPatch.OSName
		d.OSVersion = osPatch.OSVersion
		d.OSBuild = osPatch.OSBuild
		d.Platform = osPatch.Platform
	}
	if info := asMap(details["osquery_info"]); info != nil {
		d.OSQueryVersion = asString(info["version"])
	}
	if platform := asMap(details["platform_info"]); platform != nil && d.HardwareVendor == "" {
		d.HardwareVendor = asString(platform["vendor"])
	}
	return d
}
