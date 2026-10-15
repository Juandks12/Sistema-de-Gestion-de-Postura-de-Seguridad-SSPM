# Despliegue en Azure

| Pieza | Servicio | Costo |
|---|---|---|
| API (NestJS + Nmap) | Azure Container Apps, escala a cero (`westus2`) | USD 0 dentro del cupo gratis |
| Frontend | Azure Static Web Apps Free | USD 0 |
| Base de datos | PostgreSQL en Supabase (plan gratuito, `us-west-2`) | USD 0 |
| Secretos | Key Vault: `jwt-secret` y `database-url` | Centavos |
| Imagen de la API | GHCR (`ghcr.io/juandks12/sspm-api`) | USD 0 (repo público) |

La suscripción (`sub-sspm`), el estado de Terraform y la identidad de despliegue
los provee [platform-governance](https://github.com/miguelortiz13/platform-governance).
La infraestructura usa los módulos de
[terraform-modules-iac](https://github.com/miguelortiz13/terraform-modules-iac).

## Flujo

- `infra.yml`: `plan` en cada PR que toque `infra/`, `apply` en `main` con
  aprobación del environment `prod`.
- `deploy-azure.yml`, en cada push a `main` que toque `backend/` o `frontend/`:
  1. publica la imagen de la API en GHCR (`:<sha>` y `:latest`);
  2. la despliega en Container Apps y espera a `/api/v1/health` con `database: up`
     (las migraciones de Prisma corren al arrancar);
  3. compila el frontend con `VITE_API_BASE=<api>/api/v1` y lo publica en Static Web Apps.

Sin las variables de Azure del repo, los workflows solo publican la imagen y
omiten el resto.

## Configuración inicial (una vez)

### 1. Variables del repo (requiere admin del repo)

Las de la plataforma, para OIDC y estado:

```bash
R=Juandks12/Sistema-de-Gestion-de-Postura-de-Seguridad-SSPM
gh variable set AZURE_CLIENT_ID         -R $R -b <client id de id-sspm-deploy>
gh variable set AZURE_TENANT_ID         -R $R -b <tenant>
gh variable set AZURE_SUBSCRIPTION_ID   -R $R -b <id de sub-sspm>
gh variable set TFSTATE_RESOURCE_GROUP  -R $R -b rg-platform-prod-eus2
gh variable set TFSTATE_STORAGE_ACCOUNT -R $R -b sttfstate6fefa653
gh variable set TFSTATE_CONTAINER       -R $R -b sspm
```

`platform-governance/scripts/configurar-github.sh sspm` las pone solo, si quien
lo ejecuta es admin del repo. También crea el environment `prod`.

Las del despliegue, con las salidas de Terraform:

```bash
gh variable set SSPM_RESOURCE_GROUP -R $R -b rg-sspm-prod-wus2
gh variable set SSPM_API_APP        -R $R -b ca-sspm-prod-wus2-api
gh variable set SSPM_SWA_NAME       -R $R -b stapp-sspm-prod-wus2
gh variable set SSPM_API_URL        -R $R -b <salida api_url>
```

### 2. Cadena de conexión de Supabase

No pasa por Terraform (el repo es público y quedaría en el estado). Terraform
crea el secreto `database-url` con un valor provisional; el real se carga una vez:

```bash
# Supabase → Connect → Session pooler (puerto 5432; la conexión directa es solo IPv6
# y Container Apps sale por IPv4). Termina en ?sslmode=require.
az keyvault secret set --vault-name <salida key_vault_name> -n database-url --file <archivo-con-la-url> -o none
az containerapp revision restart -n ca-sspm-prod-wus2-api -g rg-sspm-prod-wus2 \
  --revision "$(az containerapp show -n ca-sspm-prod-wus2-api -g rg-sspm-prod-wus2 --query properties.latestRevisionName -o tsv)"
```

### 3. Aplicar localmente (opcional, sin CI)

```bash
cd infra/terraform
cp prod.tfvars.example prod.tfvars   # completa subscription_id
terraform init \
  -backend-config=resource_group_name=rg-platform-prod-eus2 \
  -backend-config=storage_account_name=sttfstate6fefa653 \
  -backend-config=container_name=sspm \
  -backend-config=key=terraform.tfstate \
  -backend-config=use_azuread_auth=true
terraform plan -var-file=prod.tfvars -out tfplan && terraform apply tfplan
```

## Limitaciones conocidas

- **Arranque en frío:** la API escala a cero. La primera petición tras un rato
  sin uso tarda unos segundos más.
- **Escaneos en segundo plano:** el worker de escaneos solo corre mientras la API
  está despierta; un escaneo encolado se procesa al volver a recibir tráfico.
- **Supabase gratis pausa el proyecto tras 7 días sin actividad:** se reactiva
  desde su panel.
- **Nmap desde Azure:** escanea solo activos propios o con autorización; las
  reglas de uso aceptable de Azure prohíben escanear a terceros.
