package vuln

import "testing"

func TestCompareVersions(t *testing.T) {
	eq := [][2]string{
		{"1.0", "1.0.0"},
		{"1.0.0", "1.0.0.0"},
		{"01.2", "1.2"},
		{"131.0.6778.085", "131.0.6778.85"},
		{"24B83", "24b83"},
		{"v16.90", "16.90"},
		{"6.3.1", "6.3.1.0"},
	}
	for _, pair := range eq {
		c, ok := Compare(pair[0], pair[1])
		if !ok || c != 0 {
			t.Errorf("%s vs %s = %d ok=%v, want equal", pair[0], pair[1], c, ok)
		}
	}
	less := [][2]string{
		{"1.9", "1.10"},
		{"15.2", "15.10"},
		{"15.1", "15.1.1"},
		{"131.0.6778.70", "131.0.6778.85"},
		{"131.0.6778.85", "131.0.6778.86"},
		{"130.0.6723.117", "131.0.6778.69"},
		{"9.9", "9.9p1"},
		{"9.9p1", "9.9p2"},
		{"24B83", "24B91"},
		{"24B99", "24B100"},
		{"24B91", "24C50"},
		{"1.0.0-beta", "1.0.0"},
		{"1.0.0-beta.2", "1.0.0-beta.10"},
		{"1.0.0-beta", "1.0.0-rc"},
		{"6.0.11", "6.1.0"},
		{"6.2.11.43613", "6.3.1"},
		{"127.0.6533.99", "128.0.6613.85"},
		{"128.3.0", "128.3.1"},
		{"131.0.1", "131.0.2"},
		{"1.0", "1.0-1"},
	}
	for _, pair := range less {
		c, ok := Compare(pair[0], pair[1])
		if !ok || c >= 0 {
			t.Errorf("%s should be older than %s, got %d ok=%v", pair[0], pair[1], c, ok)
		}
		rev, rok := Compare(pair[1], pair[0])
		if !rok || rev <= 0 {
			t.Errorf("%s should be newer than %s, got %d ok=%v", pair[1], pair[0], rev, rok)
		}
	}
	if _, ok := Compare("", "1.0"); ok {
		t.Fatal("empty version compared")
	}
	if _, ok := Compare("*", "1.0"); ok {
		t.Fatal("wildcard compared")
	}
	if _, ok := Compare(stringsRepeat("1", 201), "1"); ok {
		t.Fatal("overlong version compared")
	}
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}

func TestSameShapeRejectsBundleBuild(t *testing.T) {
	// Chrome's CFBundleVersion can be the trailing build (6778.86) while the
	// short version is 131.0.6778.86. Those are not the same scale.
	if SameShape("6778.86", "131.0.6778.85") {
		t.Fatal("bundle build looked comparable to a Chrome short version")
	}
	if !SameShape("131.0.6778.70", "131.0.6778.85") {
		t.Fatal("chrome short versions should compare")
	}
	if !SameShape("6.2.11.43613", "6.3.1") {
		t.Fatal("zoom long version should compare with a three-part fix")
	}
	if !SameShape("9.9p1", "9.9") {
		t.Fatal("openssh letter suffix should compare")
	}
	if !SameShape("15.1", "15.1.1") {
		t.Fatal("macos versions should compare")
	}
}

func TestMajor(t *testing.T) {
	n, ok := Major("15.1.1")
	if !ok || n != 15 {
		t.Fatalf("15.1.1 major %d %v", n, ok)
	}
	n, ok = Major("v131.0.2")
	if !ok || n != 131 {
		t.Fatalf("131 major %d %v", n, ok)
	}
	if _, ok := Major(""); ok {
		t.Fatal("empty major")
	}
}
