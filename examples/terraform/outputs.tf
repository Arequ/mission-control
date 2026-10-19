output "firefox_recipe_id" {
  value = missioncontrol_recipe.firefox.id
}

output "runner_pool" {
  value = missioncontrol_runner_pool.mac_minis.name
}

output "endpoint_log_view" {
  value = data.missioncontrol_log_view.endpoint.name
}
