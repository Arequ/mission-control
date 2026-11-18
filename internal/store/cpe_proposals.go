package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Arequ/mission-control/internal/model"
	"github.com/Arequ/mission-control/internal/vuln"
)

// CPE lookups per run. Without an API key NVD allows 5 requests per 30 s and
// the client paces at 6.5 s, so the scheduled run adds about 13 s to a sync.
const (
	cpeScheduledCalls       = 2
	cpeScheduledCallsKeyed  = 10
	cpeManualCalls          = 5
	cpeManualCallsKeyed     = 30
	cpeRecheckAfter         = 30 * 24 * time.Hour
	cpeRetryErrorAfter      = time.Hour
	cpeProposalNameMaxBytes = 200
)

// cpeSubjects lists every Munki item name the server knows: the newest
// pkginfo of each imported package, plus recipes that have not imported one
// yet (name only).
func (s *Store) cpeSubjects(ctx context.Context) ([]vuln.CPESubject, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (name) name,
			COALESCE(pkginfo->>'display_name', ''),
			COALESCE(pkginfo->>'developer', ''),
			COALESCE((
				SELECT i->>'CFBundleIdentifier'
				FROM jsonb_array_elements(CASE WHEN jsonb_typeof(pkginfo->'installs') = 'array' THEN pkginfo->'installs' ELSE '[]'::jsonb END) AS i
				WHERE jsonb_typeof(i) = 'object' AND COALESCE(i->>'CFBundleIdentifier', '') <> ''
					AND COALESCE(i->>'type', 'application') = 'application'
				LIMIT 1), '')
		FROM packages
		ORDER BY name, created_at DESC`)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []vuln.CPESubject
	for rows.Next() {
		var sub vuln.CPESubject
		if err := rows.Scan(&sub.Name, &sub.DisplayName, &sub.Developer, &sub.BundleID); err != nil {
			rows.Close()
			return nil, err
		}
		sub = cleanSubject(sub)
		if sub.Name == "" || seen[strings.ToLower(sub.Name)] {
			continue
		}
		seen[strings.ToLower(sub.Name)] = true
		out = append(out, sub)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rrows, err := s.pool.Query(ctx, `
		SELECT r.name FROM recipes r
		WHERE r.enabled AND NOT EXISTS (SELECT 1 FROM packages p WHERE p.recipe_identifier = r.identifier)
		ORDER BY r.name`)
	if err != nil {
		return nil, err
	}
	defer rrows.Close()
	for rrows.Next() {
		var name string
		if err := rrows.Scan(&name); err != nil {
			return nil, err
		}
		sub := cleanSubject(vuln.CPESubject{Name: recipeItemName(name)})
		if sub.Name == "" || seen[strings.ToLower(sub.Name)] {
			continue
		}
		seen[strings.ToLower(sub.Name)] = true
		out = append(out, sub)
	}
	return out, rrows.Err()
}

// recipeItemName strips the AutoPkg recipe type from a recipe name so
// "Granola.munki" is looked up as "Granola".
func recipeItemName(name string) string {
	name = strings.TrimSpace(name)
	for _, suffix := range []string{".munki", "-munki", ".pkg", ".download"} {
		if len(name) > len(suffix) && strings.EqualFold(name[len(name)-len(suffix):], suffix) {
			return name[:len(name)-len(suffix)]
		}
	}
	return name
}

// cleanSubject trims pkginfo strings. Pkginfo comes from recipe output, so
// oversized or control-character values are cut rather than stored.
func cleanSubject(sub vuln.CPESubject) vuln.CPESubject {
	c := func(v string) string {
		v = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, strings.TrimSpace(v))
		return clip(v, cpeProposalNameMaxBytes)
	}
	return vuln.CPESubject{Name: c(sub.Name), DisplayName: c(sub.DisplayName), Developer: c(sub.Developer), BundleID: c(sub.BundleID)}
}

type cpeRow struct {
	sub    vuln.CPESubject
	status string
	at     time.Time
}

// unmappedCPESubjects is every item without a mapping, with when it was last
// looked up (zero if never).
func (s *Store) unmappedCPESubjects(ctx context.Context, overrides []vuln.Override) ([]vuln.CPESubject, map[string]cpeRow, error) {
	subs, err := s.cpeSubjects(ctx)
	if err != nil {
		return nil, nil, err
	}
	var unmapped []vuln.CPESubject
	for _, sub := range subs {
		if _, ok := vuln.MatchMunkiName(sub.Name, overrides); ok {
			continue
		}
		unmapped = append(unmapped, sub)
	}
	rows, err := s.pool.Query(ctx, `SELECT name, display_name, developer, bundle_id, status, looked_up_at FROM cpe_proposals`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	prev := map[string]cpeRow{}
	for rows.Next() {
		var r cpeRow
		if err := rows.Scan(&r.sub.Name, &r.sub.DisplayName, &r.sub.Developer, &r.sub.BundleID, &r.status, &r.at); err != nil {
			return nil, nil, err
		}
		prev[r.sub.Name] = r
	}
	return unmapped, prev, rows.Err()
}

func cpeDue(sub vuln.CPESubject, prev cpeRow, have bool, now time.Time) bool {
	if !have || prev.sub != sub {
		return true
	}
	if prev.status == "error" {
		return now.Sub(prev.at) >= cpeRetryErrorAfter
	}
	return now.Sub(prev.at) >= cpeRecheckAfter
}

// RefreshCPEProposals looks up a bounded batch of unmapped items now. It waits
// for a running vulnerability sync so the two never share NVD's rate limit.
func (s *Store) RefreshCPEProposals(ctx context.Context) (model.CPEProposalList, error) {
	feeds := s.vulnerabilityFeeds()
	if feeds.HTTP == nil {
		return model.CPEProposalList{}, invalid("vulnerability feeds are not configured")
	}
	settings, key, err := s.loadVulnerabilitySettings(ctx, nil)
	if err != nil {
		return model.CPEProposalList{}, err
	}
	if !settings.NVDEnabled {
		return model.CPEProposalList{}, invalid("NVD is disabled in vulnerability settings")
	}
	budget := cpeManualCalls
	if strings.TrimSpace(key) != "" {
		budget = cpeManualCallsKeyed
	}
	s.vulnSyncMu.Lock()
	looked, runErr := s.proposeCPEs(ctx, feeds, settings, key, budget)
	s.vulnSyncMu.Unlock()
	list, err := s.ListCPEProposals(ctx)
	if err != nil {
		return list, err
	}
	list.LookedUp = looked
	if runErr != nil {
		return list, invalid(vuln.RedactSecret(runErr.Error(), key))
	}
	return list, nil
}

// proposeCPEs runs up to budget CPE dictionary searches. The caller holds
// vulnSyncMu. A failed request stops the batch: it is almost always a rate
// limit, the network, or a bad key, and the next item would fail the same way.
func (s *Store) proposeCPEs(ctx context.Context, feeds vuln.Feeds, settings model.VulnerabilitySettings, key string, budget int) (int, error) {
	overrides := overridesToVuln(settings.Overrides)
	subs, prev, err := s.unmappedCPESubjects(ctx, overrides)
	if err != nil {
		return 0, err
	}
	keep := make([]string, 0, len(subs))
	for _, sub := range subs {
		keep = append(keep, sub.Name)
	}
	// Items that gained a mapping or left the repo drop out of the list.
	if _, err := s.pool.Exec(ctx, `DELETE FROM cpe_proposals WHERE NOT (name = ANY($1))`, keep); err != nil {
		return 0, err
	}
	now := s.now()
	var due []vuln.CPESubject
	for _, sub := range subs {
		p, have := prev[sub.Name]
		if cpeDue(sub, p, have, now) {
			due = append(due, sub)
		}
	}
	// Never-seen items first, then the oldest lookups.
	sort.SliceStable(due, func(i, j int) bool {
		return prev[due[i].Name].at.Before(prev[due[j].Name].at)
	})

	client := &vuln.NVDClient{Base: feeds.NVDBase, Key: key, HTTP: feeds.HTTP, Sleep: feeds.Sleep, Now: feeds.Now}
	if client.Now == nil {
		client.Now = func() time.Time { return s.now() }
	}
	calls, looked := 0, 0
	for _, sub := range due {
		kws := sub.Keywords()
		if len(kws) == 0 {
			continue
		}
		if calls >= budget {
			break
		}
		var prop vuln.CPEProposal
		var used string
		total, seen := 0, 0
		for _, kw := range kws {
			if calls >= budget {
				break
			}
			page, err := client.FetchCPEs(ctx, vuln.CPEQuery{Keyword: kw, PerPage: 1000})
			calls++
			if err != nil {
				msg := vuln.RedactSecret(err.Error(), key)
				if !strings.Contains(msg, "invalid API key") {
					// The key error is about settings, not this item.
					if serr := s.saveCPEProposal(ctx, sub, kw, vuln.CPEProposal{Confidence: vuln.CPENone}, "error", msg); serr != nil {
						return looked, serr
					}
				}
				return looked, fmt.Errorf("cpe lookup %q: %s", sub.Name, msg)
			}
			used, total, seen = kw, page.Total, len(page.Entries)
			prop = vuln.ProposeCPE(sub, page.Entries)
			if prop.Confidence != vuln.CPENone {
				break
			}
		}
		if used == "" {
			break
		}
		if total > seen {
			prop.Evidence = append(prop.Evidence, fmt.Sprintf("NVD has %d CPE names for %q; the first %d were scored", total, used, seen))
		}
		status := "proposed"
		if prop.Confidence == vuln.CPENone {
			status = "no_match"
		}
		if err := s.saveCPEProposal(ctx, sub, used, prop, status, ""); err != nil {
			return looked, err
		}
		looked++
	}
	return looked, nil
}

func (s *Store) saveCPEProposal(ctx context.Context, sub vuln.CPESubject, keyword string, p vuln.CPEProposal, status, errMsg string) error {
	if p.Evidence == nil {
		p.Evidence = []string{}
	}
	if p.Candidates == nil {
		p.Candidates = []vuln.CPECandidate{}
	}
	if p.Confidence == "" {
		p.Confidence = vuln.CPENone
	}
	ev, _ := json.Marshal(p.Evidence)
	cands, _ := json.Marshal(p.Candidates)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cpe_proposals (name, display_name, developer, bundle_id, keyword, status, confidence, part, vendor, product,
			evidence, candidates, error, looked_up_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14)
		ON CONFLICT (name) DO UPDATE SET display_name=EXCLUDED.display_name, developer=EXCLUDED.developer,
			bundle_id=EXCLUDED.bundle_id, keyword=EXCLUDED.keyword, status=EXCLUDED.status, confidence=EXCLUDED.confidence,
			part=EXCLUDED.part, vendor=EXCLUDED.vendor, product=EXCLUDED.product, evidence=EXCLUDED.evidence,
			candidates=EXCLUDED.candidates, error=EXCLUDED.error, looked_up_at=EXCLUDED.looked_up_at`,
		sub.Name, sub.DisplayName, sub.Developer, sub.BundleID, keyword, status, p.Confidence, p.Part, p.Vendor, p.Product,
		string(ev), string(cands), clip(errMsg, 500), s.now())
	return err
}

var confidenceRank = map[string]int{"high": 0, "medium": 1, "low": 2, "none": 3}

// ListCPEProposals returns stored proposals for items that still have no
// mapping. An item mapped since its lookup (a new cpe_override) is left out.
func (s *Store) ListCPEProposals(ctx context.Context) (model.CPEProposalList, error) {
	settings, _, err := s.loadVulnerabilitySettings(ctx, nil)
	if err != nil {
		return model.CPEProposalList{}, err
	}
	overrides := overridesToVuln(settings.Overrides)
	subs, prev, err := s.unmappedCPESubjects(ctx, overrides)
	if err != nil {
		return model.CPEProposalList{}, err
	}
	current := map[string]bool{}
	waiting := 0
	now := s.now()
	for _, sub := range subs {
		current[sub.Name] = true
		if p, have := prev[sub.Name]; !have || p.sub != sub || (p.status == "error" && cpeDue(sub, p, have, now)) {
			waiting++
		}
	}
	rows, err := s.pool.Query(ctx, `
		SELECT name, display_name, developer, bundle_id, keyword, status, confidence, part, vendor, product,
			evidence, candidates, error, looked_up_at
		FROM cpe_proposals`)
	if err != nil {
		return model.CPEProposalList{}, err
	}
	defer rows.Close()
	out := model.CPEProposalList{Proposals: []model.CPEProposal{}, Waiting: waiting}
	for rows.Next() {
		var p model.CPEProposal
		var ev, cands []byte
		if err := rows.Scan(&p.Name, &p.DisplayName, &p.Developer, &p.BundleID, &p.Keyword, &p.Status, &p.Confidence,
			&p.Part, &p.Vendor, &p.Product, &ev, &cands, &p.Error, &p.LookedUpAt); err != nil {
			return model.CPEProposalList{}, err
		}
		if !current[p.Name] {
			continue
		}
		if err := json.Unmarshal(ev, &p.Evidence); err != nil || p.Evidence == nil {
			p.Evidence = []string{}
		}
		p.Candidates = json.RawMessage(cands)
		p.NeedsReview = p.Status == "proposed" && p.Confidence != vuln.CPEHigh
		if p.Vendor != "" && p.Product != "" {
			p.Terraform = vuln.OverrideHCL(p.Name, p.BundleID, p.Vendor, p.Product)
		}
		out.Proposals = append(out.Proposals, p)
	}
	if err := rows.Err(); err != nil {
		return model.CPEProposalList{}, err
	}
	sort.SliceStable(out.Proposals, func(i, j int) bool {
		a, b := out.Proposals[i], out.Proposals[j]
		ra, rb := confidenceRank[a.Confidence], confidenceRank[b.Confidence]
		if a.Status == "error" {
			ra = 4
		}
		if b.Status == "error" {
			rb = 4
		}
		if ra != rb {
			return ra < rb
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return out, nil
}
