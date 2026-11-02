package vuln

import (
	"sort"
	"strings"
)

// macPlatforms keeps the OS constraints a Mac can satisfy.
// ok is false when the configuration cannot apply to macOS (Windows-only,
// or an explicit "not macOS"). An empty slice with ok means any macOS version.
func macPlatforms(plats []Platform) (macs []Platform, ok bool) {
	var positive []Platform
	macAllowed := false
	nonMac := false
	for _, p := range plats {
		if p.Negate {
			if macFamily(p.Vendor, p.Product) {
				return nil, false
			}
			macAllowed = true
			continue
		}
		if macFamily(p.Vendor, p.Product) {
			positive = append(positive, p)
			macAllowed = true
			continue
		}
		nonMac = true
	}
	if len(positive) > 0 {
		return positive, true
	}
	if macAllowed && !nonMac {
		return nil, true
	}
	return nil, false
}

func macFamily(vendor, product string) bool {
	if !strings.EqualFold(vendor, "apple") {
		return false
	}
	switch strings.ToLower(product) {
	case "macos", "mac_os", "mac_os_x", "mac_os_x_server", "os_x":
		return true
	default:
		return false
	}
}

func platformOK(plats []Platform, osVersion string) bool {
	if len(plats) == 0 {
		return true
	}
	for _, p := range plats {
		hit := macPlatformHit(p, osVersion)
		if p.Negate {
			hit = !hit
		}
		if hit {
			return true
		}
	}
	return false
}

func macPlatformHit(p Platform, osVersion string) bool {
	if !macFamily(p.Vendor, p.Product) {
		return false
	}
	if !p.Bound.ranged() && p.Bound.Exact == "" {
		return true
	}
	if strings.TrimSpace(osVersion) == "" {
		return false
	}
	hit, comp := p.Bound.Affected(osVersion)
	return comp && hit
}

// EncodePlatform is the stable text stored beside a range. Empty means the
// configuration did not name an operating system.
func EncodePlatform(p Platform) string {
	if p.Vendor == "" && p.Product == "" {
		return ""
	}
	neg := "0"
	if p.Negate {
		neg = "1"
	}
	return strings.Join([]string{
		p.Vendor, p.Product,
		p.Bound.StartIncl, p.Bound.StartExcl, p.Bound.EndIncl, p.Bound.EndExcl, p.Bound.Exact,
		neg,
	}, "\x1f")
}

// EncodePlatforms stores every OS constraint on one range. The parts are
// sorted so the same set always occupies one identity.
func EncodePlatforms(ps []Platform) string {
	if len(ps) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		enc := EncodePlatform(p)
		if enc != "" {
			parts = append(parts, enc)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x1e")
}

// DecodePlatforms reverses EncodePlatforms.
func DecodePlatforms(s string) []Platform {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []Platform
	for _, part := range strings.Split(s, "\x1e") {
		p, ok := DecodePlatform(part)
		if ok {
			out = append(out, p)
		}
	}
	return out
}

// DecodePlatform reverses EncodePlatform. An empty string is no constraint.
func DecodePlatform(s string) (Platform, bool) {
	if strings.TrimSpace(s) == "" {
		return Platform{}, false
	}
	f := strings.Split(s, "\x1f")
	if len(f) != 8 {
		return Platform{}, false
	}
	return Platform{
		Vendor: f[0], Product: f[1],
		Bound: Bound{
			StartIncl: f[2], StartExcl: f[3], EndIncl: f[4], EndExcl: f[5], Exact: f[6],
		},
		Negate: f[7] == "1",
	}, true
}
