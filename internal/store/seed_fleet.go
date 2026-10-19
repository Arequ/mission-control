package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/auth"
	"github.com/Arequ/mission-control/internal/model"
)

// seedFleet inserts a local osquery catalog and about forty Macs.
// It is idempotent once any device exists. The enroll secret is the same
// kind of obvious local placeholder as MC_ADMIN_TOKEN, not a production secret.
func (s *Store) seedFleet(ctx context.Context) error {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	p := model.Principal{Kind: "system", ID: "seed", Name: "seed"}
	if _, err := s.CreateEnrollSecret(ctx, p, model.EnrollSecret{
		Name: "fleet", Secret: "mc_dev_enroll_secret", Enabled: true, ManagedBy: "terraform",
	}); err != nil {
		return err
	}
	query, err := s.CreateOsqueryQuery(ctx, p, model.OsqueryQuery{
		Name: "launch_daemons", Description: "Third-party launch daemons",
		SQL:      "SELECT name, path, program FROM launchd WHERE path LIKE '/Library/LaunchDaemons/%'",
		Platform: "darwin", Interval: 3600, Snapshot: false, Removed: true, Scheduled: false, ManagedBy: "terraform",
	})
	if err != nil {
		return err
	}
	label, err := s.CreateOsqueryLabel(ctx, p, model.OsqueryLabel{
		Name: "apple-silicon", Description: "Apple silicon Macs", Kind: "dynamic", Platform: "darwin",
		SQL: "SELECT 1 FROM system_info WHERE cpu_type = 'arm64e' OR cpu_brand LIKE '%Apple%'", ManagedBy: "terraform",
	})
	if err != nil {
		return err
	}

	now := s.now()
	type machine struct {
		model, prefix, title, cpuBrand, cpuType string
		phys, logical                           int
		memory                                  int64
	}
	hardware := []machine{
		{"Mac16,1", "MBP", "MacBook Pro", "Apple M4 Pro", "arm64e", 12, 14, 24 << 30},
		{"Mac16,7", "MBP", "MacBook Pro", "Apple M4 Max", "arm64e", 14, 16, 48 << 30},
		{"Mac16,12", "MBA", "MacBook Air", "Apple M3", "arm64e", 8, 8, 16 << 30},
		{"Mac16,13", "MBA", "MacBook Air", "Apple M3", "arm64e", 8, 10, 16 << 30},
		{"Mac16,10", "MM", "Mac mini", "Apple M4", "arm64e", 10, 10, 16 << 30},
		{"Mac14,13", "MS", "Mac Studio", "Apple M2 Ultra", "arm64e", 24, 24, 64 << 30},
		{"MacBookPro16,2", "MBP", "MacBook Pro", "Intel Core i7-8557U", "x86_64", 4, 8, 16 << 30},
	}
	type release struct{ version, build string }
	releases := []release{
		{"26.1", "25B78"},
		{"26.0.1", "25A362"},
		{"15.7.1", "24G231"},
		{"15.6.1", "24G517"},
		{"14.8", "23J20"},
	}
	depts := []string{"ENG", "DES", "SAL", "FIN", "OPS"}
	var serials []string
	for i, person := range fleetPeople {
		hw := hardware[i%len(hardware)]
		rel := releases[0]
		switch {
		case i >= 38:
			rel = releases[4]
		case i >= 35:
			rel = releases[3]
		case i >= 28:
			rel = releases[2]
		case i >= 18:
			rel = releases[1]
		}
		serial := fmt.Sprintf("MCDEV%04d", i+1)
		serials = append(serials, serial)
		id := fmt.Sprintf("dev-%04d", i+1)
		dept := depts[i%len(depts)]
		host := fmt.Sprintf("%s-%s-%04d", hw.prefix, dept, 101+i)
		name := person[0] + " " + person[1]
		enrolled := now.Add(-time.Duration(30+i) * 24 * time.Hour)
		if i < 6 {
			enrolled = now.Add(-time.Duration(i+1) * 8 * time.Hour)
		}
		seen := now.Add(-time.Duration(3+i*17) * time.Minute)
		if i >= 34 {
			seen = now.Add(-time.Duration(3+i-34) * 24 * time.Hour)
		}
		enc := i != 7 && i != 19 && i != 33
		osq := "5.15.0"
		if i%5 == 0 {
			osq = "5.14.1"
		}
		_, err = s.pool.Exec(ctx, `
			INSERT INTO devices (
				id, node_key_hash, node_invalid, host_identifier, hardware_uuid, serial, hostname, computer_name,
				platform, os_name, os_version, os_build, hardware_model, hardware_vendor, cpu_brand, cpu_type,
				cpu_physical_cores, cpu_logical_cores, physical_memory, primary_ip, primary_mac, username,
				disk_encrypted, uptime_seconds, osquery_version, apps_initialized,
				enrolled_at, last_enrolled_at, last_seen_at, created_at, updated_at)
			VALUES (
				$1,$2,false,$3,$4,$5,$6,$7,
				'darwin','macOS',$8,$9,$10,'Apple Inc.',$11,$12,
				$13,$14,$15,$16,$17,$18,
				$19,$20,$21,true,
				$22,$22,$23,$22,$23)`,
			id, auth.Hash("seed-node-"+serial),
			fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1),
			fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1),
			serial, host, name+"'s "+hw.title,
			rel.version, rel.build, hw.model, hw.cpuBrand, hw.cpuType,
			hw.phys, hw.logical, hw.memory,
			fmt.Sprintf("10.20.4.%d", 20+i),
			fmt.Sprintf("02:00:5e:%02x:%02x:%02x", 0x10, i+1, 0x40),
			strings.ToLower(person[0]+"."+person[1]),
			enc, int64((4+i%20)*3600), osq, enrolled, seen)
		if err != nil {
			return err
		}
		if err := s.seedDeviceApps(ctx, id, i); err != nil {
			return err
		}
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO osquery_label_members (label_id, device_id, source, updated_at)
		SELECT $1, id, 'sql', $2 FROM devices
		WHERE cpu_type = 'arm64e' OR cpu_brand ILIKE '%Apple%'`, label.ID, now); err != nil {
		return err
	}
	if _, err := s.CreateOsqueryLabel(ctx, p, model.OsqueryLabel{
		Name: "canaries", Description: "Machines that receive a change first", Kind: "manual",
		Serials: serials[:3], ManagedBy: "terraform",
	}); err != nil {
		return err
	}
	if _, err := s.CreateOsqueryPack(ctx, p, model.OsqueryPack{
		Name: "endpoint", Description: "Endpoint checks for Apple silicon Macs", Platform: "darwin",
		Labels: []string{"apple-silicon"}, QueryIDs: []string{query.ID}, Enabled: true, ManagedBy: "terraform",
	}); err != nil {
		return err
	}
	type ev struct {
		at     time.Time
		id     string
		action string
		detail string
	}
	events := []ev{
		{now.Add(-40 * 24 * time.Hour), "dev-0001", "enrolled", `{"hostname":"MBP-ENG-0101","os_version":"26.0.1"}`},
		{now.Add(-14 * 24 * time.Hour), "dev-0001", "os_version_changed", `{"from":"26.0.1","to":"26.1","build":"25B78"}`},
		{now.Add(-36 * time.Hour), "dev-0001", "app_updated", `{"name":"Google Chrome","from":"131.0.6778.70","to":"131.0.6778.86"}`},
		{now.Add(-9 * 24 * time.Hour), "dev-0008", "disk_encryption_changed", `{"from":true,"to":false}`},
		{now.Add(-2 * 24 * time.Hour), "dev-0003", "app_installed", `{"name":"Docker Desktop","version":"4.35.1"}`},
	}
	for _, e := range events {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO audit_log (at, actor, actor_kind, action, resource_type, resource_id, detail)
			VALUES ($1,'osquery','system',$2,'device',$3,$4::jsonb)`, e.at, e.action, e.id, e.detail); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) seedDeviceApps(ctx context.Context, deviceID string, i int) error {
	type app struct {
		name, bundle, path string
		versions           []string
	}
	catalog := []app{
		{"Google Chrome", "com.google.Chrome", "/Applications/Google Chrome.app", []string{"131.0.6778.86", "131.0.6778.70", "130.0.6723.117"}},
		{"Slack", "com.tinyspeck.slackmacgap", "/Applications/Slack.app", []string{"4.41.105", "4.40.128"}},
		{"Zoom Workplace", "us.zoom.xos", "/Applications/zoom.us.app", []string{"6.2.11.43613", "6.1.10.39410"}},
		{"1Password", "com.1password.1password", "/Applications/1Password.app", []string{"8.10.48", "8.10.46"}},
		{"Visual Studio Code", "com.microsoft.VSCode", "/Applications/Visual Studio Code.app", []string{"1.95.2", "1.94.2"}},
		{"Docker Desktop", "com.docker.docker", "/Applications/Docker.app", []string{"4.35.1", "4.34.3"}},
		{"Firefox", "org.mozilla.firefox", "/Applications/Firefox.app", []string{"132.0.1", "131.0.3"}},
		{"Microsoft Word", "com.microsoft.Word", "/Applications/Microsoft Word.app", []string{"16.90", "16.89"}},
		{"Microsoft Excel", "com.microsoft.Excel", "/Applications/Microsoft Excel.app", []string{"16.90", "16.89"}},
		{"iTerm", "com.googlecode.iterm2", "/Applications/iTerm.app", []string{"3.5.10"}},
		{"Santa", "com.northpolesec.santa", "/Applications/Santa.app", []string{"2025.9"}},
		{"Xcode", "com.apple.dt.Xcode", "/Applications/Xcode.app", []string{"16.1"}},
	}
	keep := map[int]bool{0: true, 1: true, 2: true, 3: true}
	if i%2 == 0 {
		keep[4] = true
	}
	if i%3 == 0 {
		keep[5] = true
	}
	if i%4 == 0 {
		keep[6] = true
	}
	if i%5 == 0 {
		keep[7] = true
		keep[8] = true
	}
	if i%3 == 1 {
		keep[9] = true
	}
	if i%6 == 0 {
		keep[10] = true
	}
	if i%11 == 0 {
		keep[11] = true
	}
	for idx, a := range catalog {
		if !keep[idx] {
			continue
		}
		version := a.versions[i%len(a.versions)]
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, path, bundle_id, version)
			VALUES ($1,$2,$3,$4,$5)`, deviceID, a.name, a.path, a.bundle, version); err != nil {
			return err
		}
	}
	return nil
}

var fleetPeople = [][2]string{
	{"Ava", "Thompson"},
	{"Noah", "Patel"},
	{"Mia", "Chen"},
	{"Liam", "Brooks"},
	{"Sofia", "Alvarez"},
	{"Ethan", "Nguyen"},
	{"Isla", "Rahman"},
	{"Lucas", "Bennett"},
	{"Harper", "Singh"},
	{"Owen", "Carter"},
	{"Amelia", "Rossi"},
	{"Leo", "Kim"},
	{"Chloe", "Martinez"},
	{"Jack", "Okafor"},
	{"Grace", "Murphy"},
	{"Henry", "Sato"},
	{"Ella", "Kowalski"},
	{"Sebastian", "Diaz"},
	{"Aria", "Johansson"},
	{"Mateo", "Silva"},
	{"Lily", "Berg"},
	{"Benjamin", "Cohen"},
	{"Nora", "Ibrahim"},
	{"Alexander", "Novak"},
	{"Zoe", "Andersen"},
	{"Daniel", "Park"},
	{"Hannah", "Fischer"},
	{"Samuel", "Moreau"},
	{"Layla", "Hassan"},
	{"David", "Olsen"},
	{"Victoria", "Reyes"},
	{"Joseph", "Wagner"},
	{"Scarlett", "Dubois"},
	{"Andrew", "Costa"},
	{"Penelope", "Nakamura"},
	{"Christopher", "Walsh"},
	{"Riley", "Petrov"},
	{"Nathan", "Almeida"},
	{"Audrey", "Bergstrom"},
	{"Caleb", "Okoye"},
}
