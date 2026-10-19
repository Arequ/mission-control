ALTER TABLE schedules ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC';

INSERT INTO catalogs (name, item_count, generated_at, body) VALUES
    ('all', 0, now(), '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array></array>
</plist>
')
ON CONFLICT (name) DO NOTHING;

CREATE UNIQUE INDEX packages_filename_key ON packages (filename);
