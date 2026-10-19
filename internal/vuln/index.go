package vuln

import "sort"

// Index answers which CVEs affect one product version without scanning every
// configuration in the catalog. Upper bounds are ordered so a patched version
// skips the CVEs it is already past.
type Index struct {
	byProduct map[string]*productIndex
}

type productIndex struct {
	upper []upperCVE
	other []otherCVE
	train map[string][]Train
}

type upperCVE struct {
	id        string
	end       string
	inclusive bool
	bound     ProductBound
}

type otherCVE struct {
	id    string
	bound ProductBound
}

// NewIndex groups ranges and trains by vendor and product.
func NewIndex(ranges map[string][]ProductBound, trains map[string][]Train) *Index {
	idx := &Index{byProduct: map[string]*productIndex{}}
	touch := func(vendor, product string) *productIndex {
		k := vendor + "\x00" + product
		p := idx.byProduct[k]
		if p == nil {
			p = &productIndex{train: map[string][]Train{}}
			idx.byProduct[k] = p
		}
		return p
	}
	for id, list := range ranges {
		for _, b := range list {
			p := touch(b.Vendor, b.Product)
			if upper, incl, ok := simpleUpper(b.Bound); ok && len(b.Platforms) == 0 && !AppleOS(b.Vendor, b.Product) {
				p.upper = append(p.upper, upperCVE{id: id, end: upper, inclusive: incl, bound: b})
				continue
			}
			p.other = append(p.other, otherCVE{id: id, bound: b})
		}
	}
	for id, list := range trains {
		for _, t := range list {
			p := touch(t.Vendor, t.Product)
			p.train[id] = append(p.train[id], t)
		}
	}
	for _, p := range idx.byProduct {
		sort.Slice(p.upper, func(i, j int) bool {
			c, ok := compareCore(p.upper[i].end, p.upper[j].end)
			if !ok {
				return p.upper[i].end < p.upper[j].end
			}
			return c < 0
		})
	}
	return idx
}

func simpleUpper(b Bound) (end string, inclusive, ok bool) {
	if b.Exact != "" || b.StartIncl != "" || b.StartExcl != "" {
		return "", false, false
	}
	if b.EndExcl != "" && b.EndIncl == "" {
		return b.EndExcl, false, true
	}
	if b.EndIncl != "" && b.EndExcl == "" {
		return b.EndIncl, true, true
	}
	return "", false, false
}

// ProductKey is the index key for a curated or override product.
func ProductKey(vendor, product string) string {
	return vendor + "\x00" + product
}

// MatchProduct returns the CVEs whose ranges or trains affect this install.
// Each id is returned once. The bound and train slices are the ones to pass
// to ChooseVersion and AffectedInstall.
func (idx *Index) MatchProduct(vendor, product, version, build, osVersion string) []ProductHit {
	if idx == nil {
		return nil
	}
	p := idx.byProduct[ProductKey(vendor, product)]
	if p == nil {
		return nil
	}
	// A patched install with only upper bounds does not allocate a hit map.
	if len(p.train) == 0 && len(p.other) == 0 {
		start := upperStart(p.upper, version)
		if start >= len(p.upper) {
			return nil
		}
	}
	seen := map[string]*ProductHit{}
	addRange := func(id string, b ProductBound) {
		h := seen[id]
		if h == nil {
			h = &ProductHit{CVE: id}
			seen[id] = h
		}
		h.Ranges = append(h.Ranges, b)
	}
	if len(p.train) > 0 {
		for id, ts := range p.train {
			if AffectedInstall(version, build, osVersion, nil, ts) {
				seen[id] = &ProductHit{CVE: id, Trains: ts}
			}
		}
	}
	// Upper bounds are sorted by the fix version. Everything strictly before
	// the installed version is already patched. A CVE that has a train is
	// decided by that train, so its NVD range cannot also match.
	start := upperStart(p.upper, version)
	for _, u := range p.upper[start:] {
		if len(p.train[u.id]) > 0 || AppleOS(u.bound.Vendor, u.bound.Product) {
			continue
		}
		hit, comp := u.bound.Bound.Affected(version)
		if comp && hit {
			addRange(u.id, u.bound)
		}
	}
	for _, o := range p.other {
		if len(p.train[o.id]) > 0 {
			continue
		}
		if AffectedInstall(version, build, osVersion, []ProductBound{o.bound}, nil) {
			addRange(o.id, o.bound)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]ProductHit, 0, len(seen))
	for _, h := range seen {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	return out
}

func upperStart(upper []upperCVE, version string) int {
	return sort.Search(len(upper), func(i int) bool {
		c, ok := compareCore(version, upper[i].end)
		if !ok {
			return true
		}
		if upper[i].inclusive {
			return c <= 0
		}
		return c < 0
	})
}

// ProductHit is one CVE that matches an install, with the rules that matched.
type ProductHit struct {
	CVE    string
	Ranges []ProductBound
	Trains []Train
}

// Products reports how many vendor/product pairs the index holds.
func (idx *Index) Products() int {
	if idx == nil {
		return 0
	}
	return len(idx.byProduct)
}
