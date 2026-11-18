-- The advisor's read follows a short template: a headline, up to five key
-- changes, up to two caveats, and whether the vendor says a fix is exploited.
-- notes_summary keeps the long form, shown collapsed as "More details".
ALTER TABLE release_reviews
    ADD COLUMN notes_headline TEXT NOT NULL DEFAULT '',
    ADD COLUMN notes_highlights TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN notes_caveats TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN notes_exploited BOOLEAN NOT NULL DEFAULT false;
