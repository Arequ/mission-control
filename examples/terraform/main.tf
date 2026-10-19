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

locals {
  # Event fields already shipped to Elasticsearch, mapped onto normalized device fields.
  security_field_map = {
    native_id     = "agent.id"
    serial        = "host.serial_number"
    hardware_uuid = "host.id"
    mac           = "host.mac"
    hostname      = "host.name"
    primary_user  = "user.email"
    os_version    = "host.os.version"
    ip_address    = "host.ip"
    agent_version = "agent.version"
    last_seen     = "@timestamp"
  }
}

resource "missioncontrol_source_connector" "osquery" {
  name                = "osquery"
  source              = "osquery"
  mode                = "native"
  stale_after_seconds = 86400
  interval_seconds    = 86400
}

resource "missioncontrol_source_connector" "munki" {
  name                = "munki"
  source              = "munki"
  mode                = "native"
  stale_after_seconds = 86400
  interval_seconds    = 86400
}

resource "missioncontrol_source_connector" "crowdstrike" {
  name                = "crowdstrike"
  source              = "crowdstrike"
  mode                = "api"
  base_url            = "https://api.crowdstrike.com"
  client_id           = "example-crowdstrike-client"
  client_secret       = var.crowdstrike_client_secret
  stale_after_seconds = 86400
  interval_seconds    = 86400
}

resource "missioncontrol_source_connector" "kolide" {
  name                = "kolide"
  source              = "kolide"
  mode                = "api"
  base_url            = "https://k2.kolide.com"
  api_token           = var.kolide_api_token
  stale_after_seconds = 86400
  interval_seconds    = 86400
}

resource "missioncontrol_source_connector" "rapid7" {
  name                = "rapid7"
  source              = "rapid7"
  mode                = "elastic"
  elastic_url         = "https://elasticsearch.example.invalid"
  elastic_api_key     = var.elastic_api_key
  index_pattern       = "logs-rapid7.insight-*"
  query_language      = "kql"
  query               = "event.dataset:\"rapid7.insight\""
  time_field          = "@timestamp"
  field_map           = local.security_field_map
  stale_after_seconds = 86400
  interval_seconds    = 86400
}

resource "missioncontrol_source_connector" "netskope" {
  name                = "netskope"
  source              = "netskope"
  mode                = "elastic"
  elastic_url         = "https://elasticsearch.example.invalid"
  elastic_api_key     = var.elastic_api_key
  index_pattern       = "logs-netskope.events-*"
  query_language      = "kql"
  query               = "event.dataset:\"netskope.events\""
  time_field          = "@timestamp"
  field_map           = local.security_field_map
  stale_after_seconds = 604800
  interval_seconds    = 86400
}

resource "missioncontrol_source_connector" "proofpoint" {
  name                = "proofpoint"
  source              = "proofpoint"
  mode                = "elastic"
  elastic_url         = "https://elasticsearch.example.invalid"
  elastic_api_key     = var.elastic_api_key
  index_pattern       = "logs-proofpoint.endpoint-*"
  query_language      = "kql"
  query               = "event.dataset:\"proofpoint.endpoint\""
  time_field          = "@timestamp"
  field_map           = local.security_field_map
  stale_after_seconds = 86400
  interval_seconds    = 86400
}

resource "missioncontrol_source_connector" "blastshield" {
  name                = "blastshield"
  source              = "blastshield"
  mode                = "elastic"
  elastic_url         = "https://elasticsearch.example.invalid"
  elastic_api_key     = var.elastic_api_key
  index_pattern       = "logs-blastshield.agent-*"
  query_language      = "kql"
  query               = "event.dataset:\"blastshield.agent\""
  time_field          = "@timestamp"
  field_map           = local.security_field_map
  stale_after_seconds = 86400
  interval_seconds    = 86400
}

resource "missioncontrol_log_view" "endpoint" {
  name           = "Endpoint logs"
  description    = "Munki, AutoPkg, osquery, and Falcon, merged into one timeline for a single Mac."
  default_window = "1h"
  max_lines      = 5000
  device_scoped  = true
  time_zone      = "UTC"
  connector_id   = missioncontrol_source_connector.rapid7.id

  source {
    label           = "Munki"
    color           = "#ff9f0a"
    index_pattern   = "logs-munki.install-*"
    kql             = "host.name: {{hostname}} or host.serial: {{serial}}"
    message_field   = "message"
    timestamp_field = "@timestamp"
    file_field      = "log.file.path"
    host_field      = "host.name"
    sequence_field  = "log.file.offset"
  }

  source {
    label           = "AutoPkg"
    color           = "#ffd60a"
    index_pattern   = "logs-autopkg.run-*"
    kql             = "host.name: {{hostname}}"
    message_field   = "message"
    timestamp_field = "@timestamp"
    file_field      = "log.file.path"
    host_field      = "host.name"
    sequence_field  = "log.file.offset"
  }

  source {
    label           = "osquery"
    color           = "#5e5ce6"
    index_pattern   = "logs-osquery.result-*"
    kql             = "host.name: {{hostname}} or host.uuid: {{hardware_uuid}}"
    message_field   = "message"
    timestamp_field = "@timestamp"
    file_field      = "log.file.path"
    host_field      = "host.name"
    sequence_field  = "log.file.offset"
  }

  source {
    label           = "Falcon"
    color           = "#0a84ff"
    index_pattern   = "logs-crowdstrike.falcon-*"
    kql             = "host.name: {{hostname}}"
    message_field   = "message"
    timestamp_field = "@timestamp"
    file_field      = "log.file.path"
    host_field      = "host.name"
    sequence_field  = "log.file.offset"
  }
}

resource "missioncontrol_log_view" "autopkg" {
  name            = "AutoPKG run log"
  description     = "Recipe runs on the Mac mini pool."
  default_window  = "24h"
  max_lines       = 5000
  device_scoped   = false
  time_zone       = "UTC"
  elastic_url     = "https://elasticsearch.example.invalid"
  elastic_api_key = var.elastic_api_key

  source {
    label           = "AutoPkg"
    color           = "#ffd60a"
    index_pattern   = "logs-autopkg.run-*"
    kql             = "event.dataset: \"autopkg\""
    message_field   = "message"
    timestamp_field = "@timestamp"
    file_field      = "log.file.path"
    host_field      = "host.name"
    sequence_field  = "log.file.offset"
  }
}

data "missioncontrol_log_view" "endpoint" {
  id = missioncontrol_log_view.endpoint.id
}

resource "missioncontrol_vulnerability_settings" "feeds" {
  nvd_api_key = var.nvd_api_key

  cpe_override {
    bundle_id = "com.acme.Browser"
    vendor    = "acme"
    product   = "browser"
  }
}

resource "missioncontrol_osquery_pack" "endpoint" {
  name        = "endpoint"
  description = "Endpoint checks for Apple silicon Macs"
  platform    = "darwin"
  labels      = [missioncontrol_osquery_label.apple_silicon.name]
  query_ids   = [missioncontrol_osquery_query.launch_daemons.id]
  enabled     = true
}
