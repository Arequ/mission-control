package munki

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"
)

const munki6Report = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>MachineInfo</key><dict>
  <key>hostname</key><string>mbp-eng-0217.local</string>
  <key>serial_number</key><string>C02DEMO0001</string>
  <key>os_vers</key><string>15.1.1</string>
  <key>machine_model</key><string>Mac16,8</string>
  <key>ipv4_address</key><string>10.1.2.3</string>
</dict>
<key>ManifestName</key><string>site_default</string>
<key>ManagedInstallVersion</key><string>6.6.3</string>
<key>ConsoleUser</key><string>ava</string>
<key>StartTime</key><date>2026-10-19T18:00:00Z</date>
<key>EndTime</key><date>2026-10-19T18:01:12Z</date>
<key>InstalledItems</key><array>
  <dict>
    <key>name</key><string>Firefox</string>
    <key>display_name</key><string>Firefox</string>
    <key>installed_version</key><string>132.0.1</string>
    <key>installed</key><true/>
  </dict>
  <dict>
    <key>name</key><string>Skipped</string>
    <key>installed</key><false/>
    <key>version_to_install</key><string>1</string>
  </dict>
</array>
<key>ItemsToInstall</key><array>
  <dict>
    <key>name</key><string>GoogleChrome</string>
    <key>version_to_install</key><string>131.0.6778.86</string>
  </dict>
</array>
<key>ItemsToRemove</key><array>
  <dict><key>name</key><string>OldZoom</string><key>version_to_install</key><string>6.0</string></dict>
</array>
<key>Errors</key><array><string>Could not download Slack</string></array>
<key>Warnings</key><array><string>Optional item skipped</string></array>
</dict></plist>`

const munki7Report = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>MachineInfo</key><dict>
  <key>serial_number</key><string>FVFH00000001</string>
  <key>hardware_uuid</key><string>AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE</string>
</dict>
<key>ManagedInstallVersion</key><string>7.0.1</string>
<key>ConsoleUser</key><string>ava</string>
<key>StartTime</key><date>2026-10-19T18:05:00Z</date>
<key>EndTime</key><date>2026-10-19T18:06:00Z</date>
<key>InstallResults</key><array>
  <dict><key>name</key><string>Zoom</string><key>status</key><integer>1</integer></dict>
  <dict><key>name</key><string>Firefox</string><key>status</key><integer>0</integer></dict>
</array>
<key>RemovalResults</key><array>
  <dict><key>name</key><string>Flash</string><key>status</key><integer>2</integer></dict>
</array>
<key>InstalledItems</key><array>
  <dict><key>name</key><string>Firefox</string><key>version_to_install</key><string>132.0</string></dict>
</array>
</dict></plist>`

func TestParseMunki6Report(t *testing.T) {
	r, err := ParseReport([]byte(munki6Report), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Serial != "C02DEMO0001" || r.Hostname != "mbp-eng-0217.local" || r.MunkiVersion != "6.6.3" || r.ConsoleUser != "ava" {
		t.Fatalf("%+v", r)
	}
	if r.Start.UTC() != time.Date(2026, 10, 19, 18, 0, 0, 0, time.UTC) || r.End.IsZero() {
		t.Fatalf("times %s %s", r.Start, r.End)
	}
	if len(r.Installed) != 1 || r.Installed[0].Version != "132.0.1" {
		t.Fatalf("installed %+v", r.Installed)
	}
	if len(r.Pending) != 1 || r.Pending[0].Name != "GoogleChrome" || len(r.Removals) != 1 {
		t.Fatalf("pending %+v removals %+v", r.Pending, r.Removals)
	}
	if r.Status() != "error" || len(r.Errors) != 1 || len(r.Warnings) != 1 {
		t.Fatalf("status %s %+v", r.Status(), r)
	}
}

func TestParseMunki7InstallResults(t *testing.T) {
	r, err := ParseReport([]byte(munki7Report), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.HardwareUUID == "" || r.MunkiVersion != "7.0.1" {
		t.Fatalf("%+v", r)
	}
	if r.FailedInstall != 1 || r.Status() != "error" {
		t.Fatalf("%+v", r)
	}
	joined := strings.Join(r.Errors, " ")
	if !strings.Contains(joined, "Zoom") || !strings.Contains(joined, "Flash") {
		t.Fatal(joined)
	}
}

func TestReportLimits(t *testing.T) {
	if _, err := ParseReport([]byte(`<!DOCTYPE plist [<!ENTITY x "y">]><plist version="1.0"><dict/></plist>`), nil); err == nil {
		t.Fatal("entity accepted")
	}
	deep := "<plist version=\"1.0\"><array>" + strings.Repeat("<array>", 40) + strings.Repeat("</array>", 40) + "</array></plist>"
	if _, err := ParseReport([]byte(deep), nil); err == nil {
		t.Fatal("deep plist accepted")
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(bytes.Repeat([]byte("a"), MaxReportBytes+10))
	_ = zw.Close()
	if len(buf.Bytes()) > MaxCompressedBytes {
		t.Fatal("fixture compressed too large")
	}
}

func TestDeriveDeviceTokenStable(t *testing.T) {
	a := DeriveDeviceToken("example-munki-enrollment-secret", "C02DEMO0001")
	b := DeriveDeviceToken("example-munki-enrollment-secret", "C02DEMO0001")
	if a != b || len(a) != 64 || a == DeriveDeviceToken("other-secret-value", "C02DEMO0001") {
		t.Fatal(a)
	}
}
