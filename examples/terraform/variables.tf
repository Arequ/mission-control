variable "endpoint" {
  description = "Mission Control base URL."
  type        = string
  default     = "http://localhost:8080"
}

variable "token" {
  description = "API token with config:write. The compose file seeds mc_dev_admin_token for local dev."
  type        = string
  sensitive   = true
  default     = "mc_dev_admin_token"
}

variable "max_concurrency" {
  description = "How many AutoPkg jobs may run at once across the fleet."
  type        = number
  default     = 2
}

variable "enroll_secret" {
  description = "osquery enroll secret. This example value is a placeholder for local applies, not a production secret."
  type        = string
  sensitive   = true
  default     = "example-enroll-secret"
}

variable "crowdstrike_client_secret" {
  description = "CrowdStrike OAuth client secret. Placeholder for local applies, not a production secret."
  type        = string
  sensitive   = true
  default     = "example-crowdstrike-client-secret"
}

variable "kolide_api_token" {
  description = "Kolide API token. Placeholder for local applies, not a production secret."
  type        = string
  sensitive   = true
  default     = "example-kolide-api-token"
}

variable "elastic_api_key" {
  description = "Elasticsearch API key used by the event-log connectors. Placeholder, not a production secret."
  type        = string
  sensitive   = true
  default     = "example-elastic-api-key"
}

variable "soak_days" {
  description = "Days a package stays in the testing catalog before promotion. Use 0 to promote on the next scheduler tick."
  type        = number
  default     = 7
}
