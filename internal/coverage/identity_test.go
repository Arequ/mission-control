package coverage

import "testing"

func TestNormalizeDropsPlaceholders(t *testing.T) {
	got := NormalizeKeys(Keys{
		Serial:       "  System Serial Number ",
		HardwareUUID: "{00000000-0000-0000-0000-000000000000}",
		MAC:          "00-00-00-00-00-00",
		Hostname:     "LocalHost.local",
		PrimaryUser:  "N/A",
	})
	if got != (Keys{}) {
		t.Fatalf("placeholders survived: %+v", got)
	}
	oem := NormalizeKeys(Keys{Serial: "To Be Filled By O.E.M.", HardwareUUID: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"})
	if oem.Serial != "" || oem.HardwareUUID != "" {
		t.Fatalf("oem fillers: %+v", oem)
	}
	real := NormalizeKeys(Keys{
		Serial: "mcdev0001", HardwareUUID: "ABC-DEF", MAC: "02:00:5E:10:01:40",
		Hostname: "MBP-ENG-0101.local", PrimaryUser: "Ava.Thompson",
	})
	if real.Serial != "MCDEV0001" || real.HardwareUUID != "abc-def" || real.MAC != "02:00:5e:10:01:40" || real.Hostname != "mbp-eng-0101" || real.PrimaryUser != "ava.thompson" {
		t.Fatalf("normalize: %+v", real)
	}
}

func TestResolve(t *testing.T) {
	devs := []Candidate{
		{ID: "a", Keys: Keys{Serial: "SER-A", HardwareUUID: "uuid-a", MAC: "00:1a:2b:3c:4d:0a", Hostname: "mbp-a", PrimaryUser: "ava"}},
		{ID: "b", Keys: Keys{Serial: "SER-B", HardwareUUID: "uuid-b", MAC: "00:1a:2b:3c:4d:0b", Hostname: "mba-b", PrimaryUser: "noah"}},
	}
	cases := []struct {
		name string
		obs  Keys
		want Match
	}{
		{
			name: "serial and uuid",
			obs:  Keys{Serial: "ser-a", HardwareUUID: "UUID-A"},
			want: Match{DeviceID: "a", Confidence: "strong", MatchedOn: []string{"serial", "hardware_uuid"}},
		},
		{
			name: "serial only",
			obs:  Keys{Serial: "SER-B", Hostname: "something-else"},
			want: Match{DeviceID: "b", Confidence: "strong", MatchedOn: []string{"serial"}},
		},
		{
			name: "placeholder serial still matches uuid",
			obs:  Keys{Serial: "Default string", HardwareUUID: "uuid-a"},
			want: Match{DeviceID: "a", Confidence: "strong", MatchedOn: []string{"hardware_uuid"}},
		},
		{
			name: "placeholder serial and uuid do not match",
			obs:  Keys{Serial: "0", HardwareUUID: "00000000-0000-0000-0000-000000000000", Hostname: "mbp-a"},
			want: Match{Confidence: "none"},
		},
		{
			name: "strong keys disagree",
			obs:  Keys{Serial: "SER-A", HardwareUUID: "uuid-b"},
			want: Match{Confidence: "conflict", Candidates: []string{"a", "b"}, Note: "serial and hardware UUID point at different devices"},
		},
		{
			name: "mac",
			obs:  Keys{MAC: "00-1A-2B-3C-4D-0B"},
			want: Match{DeviceID: "b", Confidence: "weak", MatchedOn: []string{"mac"}},
		},
		{
			name: "hostname plus user",
			obs:  Keys{Hostname: "MBP-A.local", PrimaryUser: "Ava"},
			want: Match{DeviceID: "a", Confidence: "weak", MatchedOn: []string{"hostname", "primary_user"}},
		},
		{
			name: "hostname alone",
			obs:  Keys{Hostname: "mbp-a"},
			want: Match{Confidence: "none"},
		},
		{
			name: "mac contradicted by serial",
			obs:  Keys{Serial: "SER-NOT-A-DEVICE", MAC: "00:1a:2b:3c:4d:0a"},
			want: Match{Confidence: "none"},
		},
		{
			name: "weak keys disagree",
			obs:  Keys{MAC: "00:1a:2b:3c:4d:0a", Hostname: "mba-b", PrimaryUser: "noah"},
			want: Match{Confidence: "conflict", Candidates: []string{"a", "b"}, Note: "MAC and hostname plus primary user point at different devices"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Resolve(tc.obs, devs)
			if got.DeviceID != tc.want.DeviceID || got.Confidence != tc.want.Confidence || got.Note != tc.want.Note {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
			if stringsJoin(got.MatchedOn) != stringsJoin(tc.want.MatchedOn) || stringsJoin(got.Candidates) != stringsJoin(tc.want.Candidates) {
				t.Fatalf("keys got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestDuplicateStrongKeyConflicts(t *testing.T) {
	devs := []Candidate{
		{ID: "a", Keys: Keys{Serial: "SAME"}},
		{ID: "b", Keys: Keys{Serial: "SAME"}},
	}
	got := Resolve(Keys{Serial: "same"}, devs)
	if got.Confidence != "conflict" || got.DeviceID != "" {
		t.Fatalf("%+v", got)
	}
}

func TestGhostKeyGroupsUnmatchedSerials(t *testing.T) {
	k := Keys{Serial: "ghost-1", Hostname: "unknown-mac"}
	a := GhostKey("crowdstrike", "cs1", k, false)
	b := GhostKey("netskope", "ns1", k, false)
	if a != b || SubjectID("", a) != SubjectID("", b) {
		t.Fatalf("ghosts should share a subject: %s %s", a, b)
	}
	conflict := GhostKey("rapid7", "r1", Keys{Serial: "SER-A", HardwareUUID: "uuid-b"}, true)
	if SubjectID("", conflict) == SubjectID("", a) {
		t.Fatal("conflict collapsed into the serial ghost")
	}
	if SubjectID("dev-1", a) != "dev-1" {
		t.Fatal("matched subject should be the device id")
	}
}

func stringsJoin(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
