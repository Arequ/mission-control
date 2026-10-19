output "firefox_recipe_id" {
  value = missioncontrol_recipe.firefox.id
}

output "runner_pool" {
  value = missioncontrol_runner_pool.mac_minis.name
}
