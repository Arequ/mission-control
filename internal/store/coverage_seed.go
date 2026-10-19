package store

import (
	"context"
	"sort"
	"time"

	"github.com/Arequ/mission-control/internal/coverage"
	"github.com/Arequ/mission-control/internal/model"
)

// seedCoverage loads connector rows and snapshots for the dev fleet.
// Credential values are the same kind of obvious local placeholder as
// MC_ADMIN_TOKEN. They are stored so the health page can show that a
// credential is set, and the API never returns them.
func (s *Store) seedCoverage(ctx context.Context) error {
	p := model.Principal{Kind: "system", ID: "seed", Name: "seed"}
	if err := s.seedConnectors(ctx, p); err != nil {
		return err
	}
	facts, err := s.loadDeviceFacts(ctx)
	if err != nil {
		return err
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	now := s.now()
	by := map[string][]coverage.Observation{}
	for i, f := range facts {
		by["osquery"] = append(by["osquery"], obsFromDevice(f, f.ID, f.LastSeen))
		if !skipSource(i, "munki") {
			o := obsFromDevice(f, "munki-"+f.Serial, seenAt(now, i, "munki"))
			o.AgentVersion = "6.6.2"
			by["munki"] = append(by["munki"], o)
		}
		for _, source := range []string{"crowdstrike", "rapid7", "netskope", "proofpoint", "blastshield", "kolide"} {
			if skipSource(i, source) {
				continue
			}
			o := obsFromDevice(f, sourcePrefix(source)+f.Serial, seenAt(now, i, source))
			o.AgentVersion = agentVersion(source)
			if i == 0 && source == "proofpoint" {
				o.Keys.Hostname = "Avas-MacBook-Pro"
			}
			if i == 2 && source == "proofpoint" {
				o.Keys.Hostname = "Mias-MacBook"
			}
			if i == 0 && source == "netskope" {
				o.OSVersion = "15.7.1"
				o.IPAddress = "192.168.1.23"
			}
			if i == 4 && source == "crowdstrike" {
				o.Keys.Serial = "System Serial Number"
			}
			by[source] = append(by[source], o)
		}
	}
	ghostA := coverage.Observation{
		NativeID: "cs-ghost-a41f", OSVersion: "15.6", IPAddress: "10.9.9.4", AgentVersion: "7.17",
		LastSeen: now.Add(-2 * time.Hour),
		Keys:     coverage.Keys{Serial: "GHOSTA41F", MAC: "02:11:22:33:44:55", Hostname: "unknown-mac-a41f"},
	}
	ghostA2 := ghostA
	ghostA2.NativeID = "ns-ghost-a41f"
	ghostA2.LastSeen = now.Add(-9 * 24 * time.Hour)
	ghostK := coverage.Observation{
		NativeID: "cs-ghost-ken", OSVersion: "14.8", IPAddress: "10.9.9.8", AgentVersion: "7.16",
		LastSeen: now.Add(-30 * time.Minute),
		Keys:     coverage.Keys{Serial: "GHOSTKEN01", Hostname: "Kens-MacBook-Air", PrimaryUser: "ken.user"},
	}
	ghostK2 := ghostK
	ghostK2.NativeID = "ns-ghost-ken"
	ghostK2.LastSeen = now.Add(-3 * time.Hour)
	ghostNew := coverage.Observation{
		NativeID: "ko-ghost-new", OSVersion: "26.1", AgentVersion: "1.4.2",
		LastSeen: now.Add(-20 * time.Minute),
		Keys:     coverage.Keys{Serial: "GHOSTNEW01", Hostname: "mba-new-hire", PrimaryUser: "new.hire"},
	}
	by["crowdstrike"] = append(by["crowdstrike"], ghostA, ghostK)
	by["netskope"] = append(by["netskope"], ghostA2, ghostK2)
	by["kolide"] = append(by["kolide"], ghostNew)
	if len(facts) > 5 {
		by["rapid7"] = append(by["rapid7"], coverage.Observation{
			NativeID: "r7-conflict", OSVersion: "26.1", LastSeen: now.Add(-time.Hour), AgentVersion: "4.0.1",
			Keys: coverage.Keys{
				Serial: facts[3].Serial, HardwareUUID: facts[5].UUID, Hostname: "conflict-host", PrimaryUser: "conflict.user",
			},
		})
	}
	for _, source := range []string{"osquery", "munki", "crowdstrike", "rapid7", "netskope", "proofpoint", "blastshield", "kolide"} {
		if err := s.ApplyObservations(ctx, source, by[source], true, false); err != nil {
			return err
		}
		status, msg := "ok", ""
		if source == "netskope" {
			status = "degraded"
			msg = "Newest event is 3h behind the other sources."
		}
		n, err := s.countSnapshots(ctx, source)
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, `
			UPDATE source_connectors
			SET last_sync_at=$2, last_sync_status=$3, last_sync_error=$4, last_sync_count=$5, updated_at=$2
			WHERE source=$1`, source, now, status, msg, n); err != nil {
			return err
		}
	}
	return s.seedCoverageEvents(ctx, now)
}

func (s *Store) seedConnectors(ctx context.Context, p model.Principal) error {
	type spec struct {
		name, source, mode, base, elastic, index, query string
		clientID                                        string
	}
	elasticMap := map[string]string{
		"native_id": "agent.id", "serial": "host.serial_number", "hardware_uuid": "host.id",
		"hostname": "host.name", "primary_user": "user.email", "mac": "host.mac",
		"os_version": "host.os.version", "ip_address": "host.ip", "agent_version": "agent.version",
		"last_seen": "@timestamp",
	}
	specs := []spec{
		{name: "osquery", source: "osquery", mode: "native"},
		{name: "munki", source: "munki", mode: "native"},
		{name: "crowdstrike", source: "crowdstrike", mode: "api", base: "https://api.crowdstrike.com", clientID: "mc_dev_crowdstrike_client"},
		{name: "kolide", source: "kolide", mode: "api", base: "https://k2.kolide.com"},
		{name: "rapid7", source: "rapid7", mode: "elastic", elastic: "https://elasticsearch.example.invalid", index: "logs-rapid7.insight-*", query: `event.dataset:"rapid7.insight"`},
		{name: "netskope", source: "netskope", mode: "elastic", elastic: "https://elasticsearch.example.invalid", index: "logs-netskope.events-*", query: `event.dataset:"netskope.events"`},
		{name: "proofpoint", source: "proofpoint", mode: "elastic", elastic: "https://elasticsearch.example.invalid", index: "logs-proofpoint.endpoint-*", query: `event.dataset:"proofpoint.endpoint"`},
		{name: "blastshield", source: "blastshield", mode: "elastic", elastic: "https://elasticsearch.example.invalid", index: "logs-blastshield.agent-*", query: `event.dataset:"blastshield.agent"`},
	}
	for _, sp := range specs {
		in := model.Connector{
			Name: sp.name, Source: sp.source, Mode: sp.mode, Enabled: true,
			IntervalSeconds: 86400, StaleAfterSeconds: 86400, ManagedBy: "terraform",
			BaseURL: sp.base, ElasticURL: sp.elastic, IndexPattern: sp.index, Query: sp.query,
			QueryLanguage: "kql", TimeField: "@timestamp", ClientID: sp.clientID,
		}
		switch sp.mode {
		case "api":
			if sp.source == "crowdstrike" {
				in.ClientSecret = "mc_dev_crowdstrike_credential"
			} else {
				in.APIToken = "mc_dev_" + sp.source + "_credential"
			}
		case "elastic":
			in.ElasticAPIKey = "mc_dev_elastic_credential"
			in.FieldMap = elasticMap
		}
		if _, err := s.CreateConnector(ctx, p, in); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) seedCoverageEvents(ctx context.Context, now time.Time) error {
	type ev struct {
		ago    time.Duration
		id     string
		source string
		kind   string
		detail string
	}
	ghost := coverage.SubjectID("", coverage.GhostKey("crowdstrike", "cs-ghost-a41f", coverage.Keys{Serial: "GHOSTA41F"}, false))
	rows := []ev{
		{40 * 24 * time.Hour, "dev-0001", "osquery", "source_seen", `{"native_id":"dev-0001","confidence":"strong","matched_on":["serial","hardware_uuid"]}`},
		{40 * 24 * time.Hour, "dev-0001", "crowdstrike", "source_seen", `{"native_id":"cs-MCDEV0001","confidence":"strong","matched_on":["serial"]}`},
		{21 * 24 * time.Hour, "dev-0001", "kolide", "source_seen", `{"native_id":"ko-MCDEV0001","confidence":"strong","matched_on":["serial"]}`},
		{14 * 24 * time.Hour, "dev-0001", "netskope", "field_disagreement", `{"field":"os_version","unified":"26.1","value":"15.7.1"}`},
		{9 * 24 * time.Hour, "dev-0001", "proofpoint", "field_disagreement", `{"field":"hostname","unified":"MBP-ENG-0101","value":"Avas-MacBook-Pro"}`},
		{6 * 24 * time.Hour, "dev-0001", "blastshield", "source_lost", `{"native_id":"bs-MCDEV0001"}`},
		{2 * 24 * time.Hour, "dev-0001", "kolide", "rematched", `{"from_device":"","to_device":"dev-0001","matched_on":["serial"],"native_id":"ko-MCDEV0001"}`},
		{3 * 24 * time.Hour, ghost, "crowdstrike", "source_seen", `{"native_id":"cs-ghost-a41f","confidence":"none"}`},
	}
	for _, e := range rows {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO coverage_events (subject_id, source, kind, detail, at)
			VALUES ($1,$2,$3,$4::jsonb,$5)`, e.id, e.source, e.kind, e.detail, now.Add(-e.ago)); err != nil {
			return err
		}
	}
	return nil
}

func obsFromDevice(f deviceFacts, nativeID string, last time.Time) coverage.Observation {
	return coverage.Observation{
		NativeID: nativeID, OSVersion: f.OS, IPAddress: f.IP, LastSeen: last,
		Keys: coverage.Keys{
			Serial: f.Serial, HardwareUUID: f.UUID, MAC: f.MAC, Hostname: f.Hostname, PrimaryUser: f.User,
		},
	}
}

func skipSource(i int, source string) bool {
	if i == 37 && source != "osquery" {
		return true
	}
	if source == "blastshield" && i%5 == 0 {
		return true
	}
	if source == "crowdstrike" && i%13 == 0 && i != 0 {
		return true
	}
	if source == "munki" && i == 7 {
		return true
	}
	return false
}

func seenAt(now time.Time, i int, source string) time.Time {
	if source == "netskope" && i%4 == 0 {
		return now.Add(-9 * 24 * time.Hour)
	}
	if source == "rapid7" && i == 15 {
		return now.Add(-8 * 24 * time.Hour)
	}
	return now.Add(-time.Duration(5+i%40) * time.Minute)
}

func sourcePrefix(source string) string {
	switch source {
	case "crowdstrike":
		return "cs-"
	case "rapid7":
		return "r7-"
	case "netskope":
		return "ns-"
	case "proofpoint":
		return "pp-"
	case "blastshield":
		return "bs-"
	case "kolide":
		return "ko-"
	default:
		return source + "-"
	}
}

func agentVersion(source string) string {
	switch source {
	case "crowdstrike":
		return "7.18"
	case "rapid7":
		return "4.0.1"
	case "netskope":
		return "124.0"
	case "proofpoint":
		return "3.6.4"
	case "blastshield":
		return "2.4"
	case "kolide":
		return "1.4.2"
	default:
		return ""
	}
}
