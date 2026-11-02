package vuln

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestIndexInclusiveUpperAndTrainsWin(t *testing.T) {
	ranges := map[string][]ProductBound{
		"CVE-2024-0001": {{
			Part: "a", Vendor: "acme", Product: "app",
			Bound: Bound{EndIncl: "1.0.0"},
		}},
		"CVE-2024-0002": {{
			Part: "a", Vendor: "acme", Product: "app",
			Bound: Bound{EndExcl: "9.0.0"},
		}},
	}
	trains := map[string][]Train{
		"CVE-2024-0002": {{
			Part: "a", Vendor: "acme", Product: "app", Major: 1,
			FixedVersion: "2.0.0", Mode: "independent",
		}},
	}
	idx := NewIndex(ranges, trains)
	hits := idx.MatchProduct("acme", "app", "1.0.0", "", "15.0")
	got := map[string]bool{}
	for _, h := range hits {
		got[h.CVE] = true
		if h.CVE == "CVE-2024-0002" && len(h.Trains) == 0 {
			t.Fatal("train lost to the wider NVD range")
		}
	}
	if !got["CVE-2024-0001"] || !got["CVE-2024-0002"] {
		t.Fatalf("hits %+v", hits)
	}
	if len(idx.MatchProduct("acme", "app", "1.0.1", "", "")) != 1 {
		t.Fatal("1.0.1 is past the inclusive bound and inside the train")
	}
	if idx.MatchProduct("acme", "app", "2.0.0", "", "") != nil {
		t.Fatal("patched train still matched")
	}
}

// TestIndexFleetScale is the 5,000 device × 300 app × 250,000 configuration
// pass. Patched installs stop at the sorted upper bound instead of walking
// every CVE.
func TestIndexFleetScale(t *testing.T) {
	const (
		products = 300
		per      = 250_000 / products
		devices  = 5000
	)
	ranges := map[string][]ProductBound{}
	for i := 0; i < products*per; i++ {
		id := fmt.Sprintf("CVE-2024-%07d", i)
		vendor := "vendor"
		product := fmt.Sprintf("app%03d", i%products)
		ranges[id] = []ProductBound{{
			Part: "a", Vendor: vendor, Product: product,
			Bound: Bound{EndExcl: "2.0.0"},
		}}
	}
	if len(ranges) != products*per {
		t.Fatalf("configs %d", len(ranges))
	}
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	started := time.Now()
	idx := NewIndex(ranges, nil)
	built := time.Since(started)
	if idx.Products() != products {
		t.Fatalf("products %d", idx.Products())
	}
	started = time.Now()
	var hits int
	for d := 0; d < devices; d++ {
		for p := 0; p < products; p++ {
			product := fmt.Sprintf("app%03d", p)
			// 1.0.0 is inside every upper bound for the product.
			// 9.0.0 is past every upper bound and must not scan them.
			version := "9.0.0"
			if d == 0 && p == 0 {
				version = "1.0.0"
			}
			matched := idx.MatchProduct("vendor", product, version, "", "15.1")
			hits += len(matched)
		}
	}
	elapsed := time.Since(started)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	var heap uint64
	if after.HeapAlloc > before.HeapAlloc {
		heap = after.HeapAlloc - before.HeapAlloc
	}
	t.Logf("index build %s match %s heap %dMiB hits %d configs %d", built, elapsed, heap>>20, hits, products*per)
	if hits != per {
		t.Fatalf("only the one vulnerable install should match, hits %d", hits)
	}
	if built > 15*time.Second || elapsed > 45*time.Second {
		t.Fatalf("matching too slow: build %s match %s", built, elapsed)
	}
	if heap > 512<<20 {
		t.Fatalf("index retained %dMiB", heap>>20)
	}
}
