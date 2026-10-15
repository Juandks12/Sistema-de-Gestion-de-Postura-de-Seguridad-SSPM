output "api_url" {
  description = "URL de la API (las rutas cuelgan de /api/v1)."
  value       = module.api.url
}

output "web_url" {
  description = "URL del frontend."
  value       = module.web.url
}

output "resource_group" {
  description = "Grupo de recursos."
  value       = module.rg.name
}

output "container_app_name" {
  description = "Container App de la API (para el despliegue continuo)."
  value       = module.api.name
}

output "static_web_app_name" {
  description = "Static Web App del frontend (para el despliegue continuo)."
  value       = module.naming.names.static_web_app
}

output "key_vault_name" {
  description = "Key Vault con jwt-secret y database-url."
  value       = module.kv.name
}
