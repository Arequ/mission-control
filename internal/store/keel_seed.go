package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Arequ/mission-control/internal/keel"
)

// seedKeel adds a few Keel devices to the dev fleet so the Configuration page
// and the device Configuration tab render something under `make server`.
// The serials are the first seeded Macs, so each one links to its device page.
// Keys are derived from the serial and are dev placeholders, not secrets.
// It is idempotent once any Keel key exists.
func (s *Store) seedKeel(ctx context.Context) error {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM keel_device_keys`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	now := s.now().UTC().Truncate(time.Second)
	munkiBase := map[string]any{
		"software_repo_url": "https://mc.example/repo",
		"client_identifier": "site_default",
		"managed_installs":  []string{"GoogleChrome", "MacadminsPython", "Slack", "Zoom"},
		"auth_header":       "[redacted]",
	}
	netskopeIDP := map[string]any{
		"mode":       "idp",
		"tenant_url": "example.goskope.com",
		"enrollment": map[string]any{"auth_token": "[redacted]", "encryption_token": "[redacted]"},
	}
	pathsd := map[string]any{"paths": []string{"/opt/coreweave/bin", "/usr/local/bin"}}
	screensaver := map[string]any{"idle_seconds": 600, "ask_for_password": true, "delay_seconds": 5}
	employeeProfiles := func(installs []string) []map[string]any {
		m := clone(munkiBase)
		if installs != nil {
			m["managed_installs"] = installs
		}
		return []map[string]any{
			{"name": "pathsd", "enabled": true, "settings": pathsd},
			{"name": "munki", "enabled": true, "settings": m},
			{"name": "netskope", "enabled": true, "settings": netskopeIDP},
			{"name": "screensaver", "enabled": true, "settings": screensaver},
			{"name": "content_caching", "enabled": false, "settings": map[string]any{}},
		}
	}
	baseline := map[string]any{"name": "baseline", "parents": []string{}}
	employee := map[string]any{"name": "employee", "parents": []string{"baseline"}, "match": "default"}

	type seedDevice struct {
		serial, hostname, model, user string
		roles                         []map[string]any
		groups                        []string
		profiles                      []map[string]any
		mode                          string
		failed                        string // resource id that fails, if any
		pending                       int    // plan-mode would_change count
		age                           time.Duration
		warnings, overlays            []string
		compileError                  bool
	}
	devices := []seedDevice{
		{
			serial: "MCDEV0001", hostname: "MBP-ENG-0101", model: "MacBook Pro (14-inch, M4 Pro)", user: "ava.thompson",
			roles: []map[string]any{baseline, employee}, groups: []string{"engineering"},
			profiles: employeeProfiles(nil), mode: "apply", age: 7 * time.Minute,
		},
		{
			serial: "MCDEV0002", hostname: "MBP-DES-0102", model: "MacBook Pro (16-inch, M4 Max)", user: "noah.patel",
			roles: []map[string]any{baseline, employee}, groups: []string{"design"},
			profiles: employeeProfiles([]string{"GoogleChrome", "MacadminsPython", "Slack", "Zoom", "Figma"}),
			mode:     "plan", pending: 2, age: 21 * time.Minute,
			warnings: []string{"netskope disabled: missing secrets [NETSKOPE_CC_ORG_KEY]"},
		},
		{
			serial: "MCDEV0003", hostname: "MBA-SAL-0103", model: "Mac mini (M4)", user: "",
			roles:  []map[string]any{baseline, {"name": "content_caching", "parents": []string{"baseline"}, "match": "marker content_caching"}},
			groups: []string{"it"}, mode: "apply", age: 3*time.Hour + 4*time.Minute,
			profiles: []map[string]any{
				{"name": "pathsd", "enabled": true, "settings": pathsd},
				{"name": "munki", "enabled": true, "settings": map[string]any{
					"software_repo_url": "https://mc.example/repo",
					"client_identifier": "content_caching",
					"managed_installs":  []string{"GoogleChrome", "MacadminsPython"},
					"auth_header":       "[redacted]",
				}},
				{"name": "netskope", "enabled": true, "settings": map[string]any{
					"mode":       "email",
					"tenant_url": "example.goskope.com",
					"email":      "content-cache@example.com",
					"enrollment": map[string]any{"auth_token": "[redacted]", "encryption_token": "[redacted]"},
				}},
				{"name": "screensaver", "enabled": false, "settings": map[string]any{}},
				{"name": "content_caching", "enabled": true, "settings": map[string]any{
					"cache_limit_gb": 200, "allow_shared_caching": true, "allow_personal_caching": false,
					"listen_ranges": []string{"10.20.0.0/16"}, "port": 49152,
				}},
			},
		},
		{
			serial: "MCDEV0004", hostname: "MBA-FIN-0104", model: "MacBook Air (15-inch, M3)", user: "liam.brooks",
			roles:  []map[string]any{baseline, employee, {"name": "it_engineer", "parents": []string{"employee"}, "match": "group it-engineering"}},
			groups: []string{"it", "it-engineering"}, mode: "apply", age: 12 * time.Minute,
			warnings: []string{"blastshield pinned to 3.4.1 by overlay 50-pilot.yaml"},
			overlays: []string{"/etc/keel/overlays.d/50-pilot.yaml"},
			failed:   "pkg[com.coreweave.blastshield]",
			profiles: append(employeeProfiles(nil), map[string]any{
				"name": "blastshield", "enabled": true, "settings": map[string]any{
					"version": "3.4.1", "enrollment_token": "[redacted]", "gateway": "bs.example.net",
				},
			}),
		},
		{
			serial: "MCDEV0005", hostname: "MBP-OPS-0105", model: "MacBook Pro (14-inch, M4 Pro)", user: "sofia.alvarez",
			groups: []string{"ops"}, mode: "apply", age: 9 * time.Minute, compileError: true,
			warnings: []string{"compile: roles/employee.yaml:14: unknown profile \"dockutil\""},
		},
	}
	for _, d := range devices {
		seed := sha256.Sum256([]byte("mission-control-dev-keel-" + d.serial))
		priv := ed25519.NewKeyFromSeed(seed[:])
		pub := priv.Public().(ed25519.PublicKey)
		last := now.Add(-d.age)
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO keel_device_keys (serial, hostname, public_key, enroll_secret_id, enrolled_at, last_timestamp, last_report_at)
			VALUES ($1,$2,$3,'seed',$4,$5,$6)`,
			d.serial, d.hostname, []byte(pub), now.Add(-20*24*time.Hour), last.Unix(), last); err != nil {
			return err
		}
		// Three runs per device, 30 minutes apart; the oldest one had a failure
		// on the first device so the history is not uniform.
		for i := 2; i >= 0; i-- {
			at := last.Add(-time.Duration(i) * 30 * time.Minute)
			failed := d.failed
			if d.serial == "MCDEV0001" && i == 2 {
				failed = "launchd[com.coreweave.cinc-health]"
			}
			mode := d.mode
			pending := d.pending
			if mode == "plan" && i > 0 {
				mode, pending = "apply", 0
			}
			doc := seedKeelBody(d.serial, d.hostname, d.model, d.user, d.groups, d.roles, d.profiles, mode, failed, pending, at, i)
			if d.warnings != nil {
				doc["warnings"] = d.warnings
			}
			if d.overlays != nil {
				doc["overlays"] = d.overlays
			}
			if d.compileError {
				doc["roles"], doc["profiles"], doc["resources"] = []any{}, []any{}, []any{}
				doc["summary"] = map[string]int{"total": 0, "ok": 0, "changed": 0, "would_change": 0, "failed": 0, "skipped": 0}
			}
			body, err := json.Marshal(doc)
			if err != nil {
				return err
			}
			report, err := keel.ParseReport(body, d.serial)
			if err != nil {
				return err
			}
			tx, err := s.pool.Begin(ctx)
			if err != nil {
				return err
			}
			if err := insertKeelRun(ctx, tx, report, at.Unix(), at, body); err != nil {
				_ = tx.Rollback(ctx)
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func seedKeelBody(serial, hostname, model, user string, groups []string, roles, profiles []map[string]any,
	mode, failed string, pending int, at time.Time, n int) map[string]any {
	type res struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Profile    string `json:"profile"`
		Status     string `json:"status"`
		Message    string `json:"message"`
		DurationMS int    `json:"duration_ms"`
	}
	resources := []res{
		{"file[/etc/paths.d/cpe_pathsd]", "file", "pathsd", "ok", "", 1},
		{"directory[/opt/coreweave/bin]", "directory", "pathsd", "ok", "", 0},
		{"defaults[/Library/Preferences/ManagedInstalls]", "defaults", "munki", "ok", "", 6},
		{"file[/Library/Managed Installs/manifests/SelfServeManifest]", "file", "munki", "ok", "", 2},
		{"pkg[com.netskope.client.Netskope-Client]", "pkg", "netskope", "ok", "", 14},
		{"file[/Library/Application Support/Netskope/STAgent/nsbranding.json]", "file", "netskope", "ok", "", 2},
		{"launchd[com.coreweave.cinc-health]", "launchd", "pathsd", "ok", "", 3},
	}
	enabled := map[string]bool{}
	for _, p := range profiles {
		if p["enabled"] == true {
			enabled[p["name"].(string)] = true
		}
	}
	if enabled["screensaver"] {
		resources = append(resources, res{"defaults[com.apple.screensaver]", "defaults", "screensaver", "ok", "", 4})
	} else {
		resources = append(resources, res{"defaults[com.apple.screensaver]", "defaults", "screensaver", "skipped", "profile disabled for this role", 0})
	}
	if enabled["content_caching"] {
		resources = append(resources,
			res{"defaults[/Library/Preferences/com.apple.AssetCache]", "defaults", "content_caching", "ok", "", 5},
			res{"execute[AssetCacheManagerUtil activate]", "execute", "content_caching", "ok", "", 220})
	}
	if enabled["blastshield"] {
		resources = append(resources, res{"pkg[com.coreweave.blastshield]", "pkg", "blastshield", "ok", "", 40})
	}
	if n == 0 && mode == "apply" && serial == "MCDEV0001" {
		resources[2].Status = "changed"
	}
	for i := range resources {
		if resources[i].ID == failed {
			resources[i].Status = "failed"
			resources[i].Message = "installer exited 1: package signature not trusted"
			if failed == "launchd[com.coreweave.cinc-health]" {
				resources[i].Message = "launchctl bootstrap: 5: Input/output error"
			}
		}
	}
	for i := 0; i < pending && i < len(resources)-1; i++ {
		resources[len(resources)-2-i].Status = "would_change"
	}
	sum := map[string]int{"total": len(resources), "ok": 0, "changed": 0, "would_change": 0, "failed": 0, "skipped": 0}
	for _, r := range resources {
		sum[r.Status]++
	}
	facts := map[string]any{
		"serial": serial, "hostname": hostname, "model": model, "os_version": "26.1", "arch": "arm64",
		"console_user": user, "groups": groups, "markers": []string{},
		"filevault": true, "sip": true, "uptime_hours": 31 + n,
	}
	body := map[string]any{
		"schema":       keel.Schema,
		"run_id":       fmt.Sprintf("seed-%s-%d", serial, at.Unix()),
		"keel_version": "0.1.0+abc1234",
		"mode":         mode,
		"started_at":   at.Add(-2 * time.Second).Format(time.RFC3339),
		"duration_ms":  640 + 37*n + len(resources)*11,
		"device": map[string]any{
			"serial": serial, "hostname": hostname, "model": model, "os_version": "26.1",
			"arch": "arm64", "console_user": user,
		},
		"roles":     roles,
		"facts":     facts,
		"profiles":  profiles,
		"resources": resources,
		"summary":   sum,
	}
	return body
}
