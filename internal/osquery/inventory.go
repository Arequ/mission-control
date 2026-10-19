// Package osquery holds the agent-facing query catalog and the result forwarder.
package osquery

// Built-in inventory query names. They are reserved: Terraform query names
// cannot start with mc_.
const (
	QSystemInfo         = "mc_system_info"
	QOSVersion          = "mc_os_version"
	QOsqueryInfo        = "mc_osquery_info"
	QInterfaceAddresses = "mc_interface_addresses"
	QInterfaceDetails   = "mc_interface_details"
	QLoggedInUsers      = "mc_logged_in_users"
	QApps               = "mc_apps"
	QDiskEncryption     = "mc_disk_encryption"
	QUptime             = "mc_uptime"
	labelPrefix         = "mc_label_"
)

// ScheduledQuery is one query placed on the osquery schedule.
type ScheduledQuery struct {
	Name     string
	SQL      string
	Platform string
	Snapshot bool
}

// InventoryQueries are refreshed on the server's inventory interval.
// Snapshot results replace the stored set so change detection has a full picture.
func InventoryQueries() []ScheduledQuery {
	return []ScheduledQuery{
		{Name: QSystemInfo, Snapshot: true, SQL: `SELECT hostname, uuid, cpu_type, cpu_brand, cpu_physical_cores, cpu_logical_cores, physical_memory, hardware_vendor, hardware_model, hardware_serial, computer_name, local_hostname FROM system_info`},
		{Name: QOSVersion, Snapshot: true, SQL: `SELECT name, version, major, minor, patch, build, platform FROM os_version`},
		{Name: QOsqueryInfo, Snapshot: true, SQL: `SELECT version, config_hash FROM osquery_info`},
		{Name: QInterfaceAddresses, Snapshot: true, SQL: `SELECT interface, address, mask, type FROM interface_addresses`},
		{Name: QInterfaceDetails, Snapshot: true, SQL: `SELECT interface, mac, type FROM interface_details`},
		{Name: QLoggedInUsers, Snapshot: true, SQL: `SELECT type, user, tty, host FROM logged_in_users`},
		{Name: QApps, Snapshot: true, Platform: "darwin", SQL: `SELECT name, path, bundle_identifier, bundle_short_version FROM apps`},
		{Name: QDiskEncryption, Snapshot: true, Platform: "darwin,windows", SQL: `SELECT name, uuid, encrypted FROM disk_encryption`},
		{Name: QUptime, Snapshot: true, SQL: `SELECT total_seconds FROM uptime`},
	}
}

// LabelQueryName is the schedule key for a dynamic label.
func LabelQueryName(label string) string { return labelPrefix + label }

// LabelFromQuery returns the label name when the schedule key is a label query.
func LabelFromQuery(name string) (string, bool) {
	if len(name) <= len(labelPrefix) || name[:len(labelPrefix)] != labelPrefix {
		return "", false
	}
	return name[len(labelPrefix):], true
}

// IsInventory reports whether the query name updates the normalized device record.
func IsInventory(name string) bool {
	switch name {
	case QSystemInfo, QOSVersion, QOsqueryInfo, QInterfaceAddresses, QInterfaceDetails, QLoggedInUsers, QApps, QDiskEncryption, QUptime:
		return true
	default:
		return false
	}
}
