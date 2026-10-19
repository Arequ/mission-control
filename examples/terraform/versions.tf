terraform {
  required_version = ">= 1.11.0"
  required_providers {
    missioncontrol = {
      source = "arequ/missioncontrol"
    }
  }
}

provider "missioncontrol" {
  endpoint = var.endpoint
  token    = var.token
}
