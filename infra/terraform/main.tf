# SSPM en la capa gratuita de Azure:
#   API (NestJS + Nmap) en Container Apps, escala a cero
#   Frontend (React) en Static Web Apps Free
#   Base de datos PostgreSQL en Supabase (plan gratuito, fuera de Azure)
#   Secretos (cadena de conexión, JWT) en Key Vault
# Costo esperado: USD 0 dentro de los cupos de la suscripción.

data "azurerm_client_config" "current" {}

module "naming" {
  source = "git::https://github.com/miguelortiz13/terraform-modules-iac.git//modules/azure/naming?ref=v0.3.0"

  project     = "sspm"
  environment = "prod"
  location    = var.location
  unique_seed = data.azurerm_client_config.current.subscription_id
  owner       = var.owner
  repository  = "Juandks12/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM"
}

module "rg" {
  source = "git::https://github.com/miguelortiz13/terraform-modules-iac.git//modules/azure/resource-group?ref=v0.3.0"

  name     = module.naming.names.resource_group
  location = var.location
  tags     = module.naming.tags
}

# Identidad de la API: lee sus secretos de Key Vault sin credenciales.
module "api_identity" {
  source = "git::https://github.com/miguelortiz13/terraform-modules-iac.git//modules/azure/user-assigned-identity?ref=v0.3.0"

  name                = "${module.naming.names.user_assigned_identity}-api"
  resource_group_name = module.rg.name
  location            = module.rg.location
  tags                = module.naming.tags
}

# ---------------------------------------------------------------------------
# Secretos
# ---------------------------------------------------------------------------
module "kv" {
  source = "git::https://github.com/miguelortiz13/terraform-modules-iac.git//modules/azure/key-vault?ref=v0.3.0"

  name                = module.naming.names.key_vault
  resource_group_name = module.rg.name
  location            = module.rg.location
  tags                = module.naming.tags
  tenant_id           = data.azurerm_client_config.current.tenant_id

  # Demo: permite recrear el vault con el mismo nombre tras un destroy.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  role_assignments = {
    api = { principal_id = module.api_identity.principal_id, role_definition_name = "Key Vault Secrets User" }
    deployer = {
      principal_id         = data.azurerm_client_config.current.object_id
      role_definition_name = "Key Vault Secrets Officer"
      principal_type       = data.azurerm_client_config.current.object_id == "d00f7e88-2392-436e-9ae1-4d7c80253dea" ? "User" : "ServicePrincipal"
    }
  }
}

# Los permisos de RBAC tardan en propagarse antes de poder escribir secretos.
resource "time_sleep" "kv_rbac" {
  create_duration = "60s"
  depends_on      = [module.kv]
}

resource "random_password" "jwt" {
  length  = 64
  special = false
}

resource "azurerm_key_vault_secret" "jwt" {
  name         = "jwt-secret"
  key_vault_id = module.kv.id
  value        = random_password.jwt.result
  content_type = "text/plain"

  depends_on = [time_sleep.kv_rbac]
}

# La cadena de conexión de Supabase NO pasa por Terraform (no queda en el
# estado ni en el repo, que es público). Terraform crea el secreto vacío y el
# valor real se carga una vez fuera de banda (ver infra/README.md):
#   az keyvault secret set --vault-name <kv> -n database-url --file <archivo>
resource "azurerm_key_vault_secret" "database_url" {
  name         = "database-url"
  key_vault_id = module.kv.id
  value        = "pendiente"
  content_type = "text/plain"

  lifecycle {
    ignore_changes = [value]
  }

  depends_on = [time_sleep.kv_rbac]
}

# ---------------------------------------------------------------------------
# Frontend y API
# ---------------------------------------------------------------------------
module "web" {
  source = "git::https://github.com/miguelortiz13/terraform-modules-iac.git//modules/azure/static-web-app?ref=v0.3.0"

  name                = module.naming.names.static_web_app
  resource_group_name = module.rg.name
  location            = var.location
  tags                = module.naming.tags
}

module "cae" {
  source = "git::https://github.com/miguelortiz13/terraform-modules-iac.git//modules/azure/container-app-environment?ref=v0.3.0"

  name                = module.naming.names.container_app_environment
  resource_group_name = module.rg.name
  location            = module.rg.location
  tags                = module.naming.tags
}

module "api" {
  source = "git::https://github.com/miguelortiz13/terraform-modules-iac.git//modules/azure/container-app?ref=v0.3.0"

  name                         = "${module.naming.names.container_app}-api"
  resource_group_name          = module.rg.name
  container_app_environment_id = module.cae.id
  tags                         = module.naming.tags

  image        = var.api_image
  cpu          = 0.5
  memory       = "1Gi"
  min_replicas = 0
  max_replicas = 1

  ingress           = { target_port = 3000 }
  health_probe_path = "/api/v1/health"
  identity_ids      = [module.api_identity.id]

  key_vault_secrets = {
    "jwt-secret"   = azurerm_key_vault_secret.jwt.versionless_id
    "database-url" = azurerm_key_vault_secret.database_url.versionless_id
  }

  # Variable de entorno => nombre del secreto de Key Vault (no son valores).
  secret_env = {
    JWT_SECRET   = "jwt-secret"
    DATABASE_URL = "database-url"
  }

  env = {
    NODE_ENV     = "production"
    CORS_ORIGINS = module.web.url
    # Un salto: el ingress de Container Apps. Así los límites del login ven la
    # IP real del cliente.
    TRUST_PROXY = "1"
    # Con escala a cero el worker solo corre mientras la API está despierta:
    # un escaneo encolado se procesa en la siguiente petición.
    SCAN_MAX_CONCURRENCY = "1"
  }
}
