resource "missioncontrol_runner_pool" "mac_minis" {
  name        = "mac-minis"
  description = "Mac minis and EC2 Mac hosts that run AutoPkg"
  labels      = ["macos", "autopkg"]
}

resource "missioncontrol_recipe_repo" "recipes" {
  name = "autopkg-recipes"
  url  = "https://github.com/autopkg/recipes.git"
  ref  = "master"
}

resource "missioncontrol_recipe" "firefox" {
  identifier     = "local.munki.Firefox"
  name           = "Firefox"
  repo_id        = missioncontrol_recipe_repo.recipes.id
  runner_pool_id = missioncontrol_runner_pool.mac_minis.id
  enabled        = true
  labels         = ["macos", "autopkg"]
  override       = file("${path.module}/overrides/Firefox.recipe")
  trust_info     = jsonencode(jsondecode(file("${path.module}/trust/Firefox.json")))
}

resource "missioncontrol_schedule" "firefox_morning" {
  name      = "firefox-morning"
  recipe_id = missioncontrol_recipe.firefox.id
  # Five-field cron. A new schedule waits for the next instant;
  # enqueue immediately with POST /api/v1/jobs {"recipe_id": "..."}.
  cron    = "15 6 * * *"
  enabled = true
}

resource "missioncontrol_pipeline_settings" "fleet" {
  max_concurrency        = var.max_concurrency
  per_runner_parallelism = 1
  timeout_seconds        = 3600
  max_retries            = 2
  lease_seconds          = 300
}

resource "missioncontrol_promotion_rule" "testing_to_production" {
  name         = "testing-to-production"
  from_catalog = "testing"
  to_catalog   = "production"
  soak_days    = var.soak_days
  manual_hold  = false
  enabled      = true
}

resource "missioncontrol_manifest" "site_default" {
  name             = "site_default"
  catalogs         = ["production"]
  managed_installs = ["Firefox"]
}

resource "missioncontrol_manifest" "testing" {
  name             = "testing"
  catalogs         = ["testing", "production"]
  managed_installs = ["Firefox"]
}

resource "missioncontrol_osquery_enroll_secret" "fleet" {
  name    = "fleet"
  secret  = var.enroll_secret
  enabled = true
}

resource "missioncontrol_osquery_label" "apple_silicon" {
  name        = "apple-silicon"
  description = "Apple silicon Macs"
  kind        = "dynamic"
  platform    = "darwin"
  sql         = "SELECT 1 FROM system_info WHERE cpu_type = 'arm64e' OR cpu_brand LIKE '%Apple%';"
}

resource "missioncontrol_osquery_label" "canaries" {
  name        = "canaries"
  description = "Machines that receive a change first"
  kind        = "manual"
  serials     = []
}

resource "missioncontrol_osquery_query" "launch_daemons" {
  name        = "launch_daemons"
  description = "Third-party launch daemons"
  sql         = "SELECT name, path, program FROM launchd WHERE path LIKE '/Library/LaunchDaemons/%';"
  platform    = "darwin"
  interval    = 3600
  snapshot    = false
  removed     = true
  scheduled   = false
}

resource "missioncontrol_osquery_pack" "endpoint" {
  name        = "endpoint"
  description = "Endpoint checks for Apple silicon Macs"
  platform    = "darwin"
  labels      = [missioncontrol_osquery_label.apple_silicon.name]
  query_ids   = [missioncontrol_osquery_query.launch_daemons.id]
  enabled     = true
}
