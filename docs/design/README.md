# Design

The UI source of truth in this repo is `web/src/styles.css`. Its first comment records that the tokens came from the approved mockup `app.css`, including the web-shell overrides. There is no component library and no Tailwind setup.

Rules:

- Use the tokens in that file (`--accent`, `--text`, `--card`, `--sep`, the status colors, `--ease`). Do not add a second palette.
- Motion is CSS `transform` and `opacity` only. `prefers-reduced-motion` disables it.
- Light and dark both have to work. Dark mode is `html.dark`.
- Pages stay sparse next to the original fleet and device mockups: type, color, radii, frosted shell, cards, and pills. Source tiles use two-letter initials, not logos.
- Config is read-only. A violet Managed by Terraform badge, and a Propose change link when `internal/configrepo` has a file for that kind.

The original `mockups-src.tgz` (the `app.css` file plus the fleet and device mockup images) was an attachment to the design review and is not in this git history. Do not invent a replacement stylesheet. If that archive is available again, add it beside this file.
