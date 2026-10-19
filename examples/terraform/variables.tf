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

variable "soak_days" {
  description = "Days a package stays in the testing catalog before promotion. Use 0 to promote on the next scheduler tick."
  type        = number
  default     = 7
}
