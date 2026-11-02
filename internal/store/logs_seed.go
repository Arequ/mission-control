package store

import (
	"context"

	"github.com/Arequ/mission-control/internal/model"
)

// seedLogViews inserts the dev log views once. They read a built-in corpus
// so the UI works without Elasticsearch. Names overlap examples/terraform;
// apply that stack to a database that was not seeded.
func (s *Store) seedLogViews(ctx context.Context) error {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM log_views`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	p := model.Principal{Kind: "system", ID: "seed", Name: "seed"}
	views := []model.LogView{
		{
			Name: "Endpoint logs", Description: "Munki, AutoPkg, osquery, and Falcon, one timeline for this Mac.",
			DefaultWindow: "1h", MaxLines: 5000, DeviceScoped: true, TimeZone: "UTC", ManagedBy: "terraform",
			Sources: []model.LogSource{
				src("Munki", "#ff9f0a", "logs-munki.install-*", `host.name: {{hostname}} or host.serial: {{serial}}`, "/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log"),
				src("AutoPkg", "#ffd60a", "logs-autopkg.run-*", `host.name: {{hostname}}`, "/Library/AutoPkg/Logs/autopkg.log"),
				src("osquery", "#5e5ce6", "logs-osquery.result-*", `host.name: {{hostname}} or host.uuid: {{hardware_uuid}}`, "/var/log/osquery/osqueryd.results.log"),
				src("Falcon", "#0a84ff", "logs-crowdstrike.falcon-*", `host.name: {{hostname}}`, "/Library/CS/Logs/falconctl.log"),
			},
		},
		{
			Name: "Munki install log", Description: "ManagedSoftwareUpdate.log for one Mac.",
			DefaultWindow: "6h", MaxLines: 8000, DeviceScoped: true, TimeZone: "America/Los_Angeles", ManagedBy: "terraform",
			Sources: []model.LogSource{
				src("Munki", "#ff9f0a", "logs-munki.install-*", `host.serial: {{serial}}`, "/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log"),
			},
		},
		{
			Name: "AutoPKG run log", Description: "Recipe runs on the Mac mini pool.",
			DefaultWindow: "24h", MaxLines: 5000, DeviceScoped: false, TimeZone: "UTC", ManagedBy: "terraform",
			Sources: []model.LogSource{
				src("AutoPkg", "#ffd60a", "logs-autopkg.run-*", `event.dataset: "autopkg"`, "/Library/AutoPkg/Logs/autopkg.log"),
			},
		},
		{
			Name: "osquery errors", Description: "osqueryd errors for one Mac.",
			DefaultWindow: "1h", MaxLines: 5000, DeviceScoped: true, TimeZone: "UTC", ManagedBy: "terraform",
			Sources: []model.LogSource{
				src("osquery", "#5e5ce6", "logs-osquery.result-*", `host.name: {{hostname}} and log.level: "error"`, "/var/log/osquery/osqueryd.results.log"),
			},
		},
		{
			Name: "Falcon sensor", Description: "CrowdStrike sensor log for one Mac.",
			DefaultWindow: "1h", MaxLines: 5000, DeviceScoped: true, TimeZone: "UTC", ManagedBy: "terraform",
			Sources: []model.LogSource{
				src("Falcon", "#0a84ff", "logs-crowdstrike.falcon-*", `host.serial: {{serial}}`, "/Library/CS/Logs/falconctl.log"),
			},
		},
	}
	for _, v := range views {
		if _, err := s.insertLogView(ctx, p, v, "seed"); err != nil {
			return err
		}
	}
	return nil
}

func src(label, color, index, kql, _ string) model.LogSource {
	return model.LogSource{
		Label: label, Color: color, IndexPattern: index, KQL: kql,
		MessageField: "message", TimestampField: "@timestamp",
		FileField: "log.file.path", HostField: "host.name", SequenceField: "log.file.offset",
	}
}
