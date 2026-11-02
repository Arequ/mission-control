-- Platform constraints on NVD ranges, and indexes for product matching and the issue list.

ALTER TABLE vuln_ranges ADD COLUMN platform TEXT NOT NULL DEFAULT '';

DROP INDEX vuln_ranges_identity;
CREATE UNIQUE INDEX vuln_ranges_identity ON vuln_ranges (
    cve_id, part, vendor, product, start_incl, start_excl, end_incl, end_excl, exact, platform
);

CREATE INDEX vuln_ranges_product_idx ON vuln_ranges (vendor, product, cve_id);
CREATE INDEX vuln_trains_product_idx ON vuln_trains (vendor, product, cve_id);
CREATE INDEX vuln_issues_list_idx ON vuln_issues (status, cve_id, software_key);
CREATE INDEX vuln_cves_priority_idx ON vuln_cves (kev DESC, epss DESC, cvss_score DESC, cve_id);
