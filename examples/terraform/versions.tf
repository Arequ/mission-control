terraform {
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
