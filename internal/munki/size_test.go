package munki

import "testing"

func TestInstallerItemSizeTruncatesLikeMakepkginfo(t *testing.T) {
	cases := []struct {
		n    int
		want int64
	}{
		{100, 0},
		{1024, 1},
		{1025, 1},
		{1500, 1},
		{2048, 2},
	}
	for _, tc := range cases {
		info := map[string]any{}
		ApplyArtifact(info, "App.pkg", make([]byte, tc.n), "testing")
		if info["installer_item_size"] != tc.want {
			t.Fatalf("%d bytes -> %#v", tc.n, info["installer_item_size"])
		}
		cats, _ := info["catalogs"].([]any)
		if len(cats) != 1 || cats[0] != "testing" {
			t.Fatalf("catalogs %#v", info["catalogs"])
		}
	}
}

func TestSoakDurationRejectsOverflow(t *testing.T) {
	if _, ok := SoakDuration(2000000000); ok {
		t.Fatal("huge soak accepted")
	}
	if _, ok := SoakDuration(-1); ok {
		t.Fatal("negative soak accepted")
	}
	d, ok := SoakDuration(7)
	if !ok || d.Hours() != 24*7 {
		t.Fatalf("7 days = %s ok=%v", d, ok)
	}
}
