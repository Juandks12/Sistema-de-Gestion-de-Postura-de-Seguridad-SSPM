# Modelo de Datos y Esquema de Base de Datos

> **Sistema de Gestión de Postura de Seguridad (SSPM / EASM / CSPM)**  
> Versión: **2.0.0**  
> Motor: **PostgreSQL 16 + Prisma ORM 6**

Este documento detalla el modelo de datos relacional de la plataforma, el diagrama Entidad-Relación (ERD), la definición de tablas, relaciones, índices de rendimiento y las políticas de integridad multi-tenancy.

---

## 1. Diagrama Entidad-Relación (ERD)

```mermaid
erDiagram
    organizations ||--o{ users : "tiene"
    organizations ||--o{ assets : "posee"
    organizations ||--o{ cloud_accounts : "conecta"
    organizations ||--o{ alerts : "genera"
    organizations ||--o{ alert_channels : "configura"
    organizations ||--o{ reports : "emite"
    organizations ||--o{ audit_logs : "registra"
    organizations ||--o{ api_keys : "emite"
    organizations ||--o{ account_tokens : "asigna"

    assets ||--o{ scans : "ejecuta"
    assets ||--o{ diagnostic_batches : "orquesta"
    assets ||--o{ findings : "presenta"
    assets ||--o{ scan_ports : "expone"
    assets ||--o{ discovered_hosts : "descubre"
    assets ||--o| cloud_accounts : "asocia"

    cloud_accounts ||--o{ cloud_resources : "inventaria"
    cloud_accounts ||--o{ findings : "origina"
    cloud_resources ||--o{ findings : "asocia"

    scans ||--o{ scan_ports : "detecta"
    scans }o--|| diagnostic_batches : "pertenece"
    scans ||--o{ findings : "detecta_en"
    scans ||--o{ alerts : "dispara"
    scans ||--o{ discovered_hosts : "origina"

    users ||--o{ findings : "asignado_a"
    users ||--o{ reports : "generado_por"
    users ||--o{ diagnostic_batches : "solicitado_por"
    users ||--o{ alert_channels : "creado_por"

    organizations {
        uuid id PK
        string name
        string slug UK
        boolean is_active
        string monitoring_frequency
        string verification_token UK
        timestamp created_at
        timestamp updated_at
    }

    users {
        uuid id PK
        uuid organization_id FK
        string email UK
        string password_hash
        string full_name
        string role
        boolean is_active
        boolean mfa_enabled
        string mfa_secret
        integer token_version
        timestamp created_at
    }

    assets {
        uuid id PK
        uuid organization_id FK
        string type
        string value
        string name
        string criticality
        string[] tags
        boolean is_active
        boolean authorization_confirmed
        timestamp verified_at
        string verification_method
        string verification_scope
        timestamp last_scanned_at
    }

    diagnostic_batches {
        uuid id PK
        uuid organization_id FK
        uuid asset_id FK
        uuid requested_by_id FK
        string profile
        string status
        integer current_stage
        integer total_stages
        json summary
        timestamp started_at
        timestamp finished_at
    }

    scans {
        uuid id PK
        uuid organization_id FK
        uuid asset_id FK
        uuid batch_id FK
        string type
        string status
        string source
        integer stage
        string target_address
        json parameters
        json summary
        json raw_result
        timestamp started_at
        timestamp finished_at
    }

    scan_ports {
        uuid id PK
        uuid organization_id FK
        uuid scan_id FK
        uuid asset_id FK
        integer port
        string protocol
        string state
        string service_name
        string product
        string version
        string[] cpe
    }

    findings {
        uuid id PK
        uuid organization_id FK
        uuid asset_id FK
        uuid last_scan_id FK
        uuid cloud_account_id FK
        uuid cloud_resource_id FK
        string rule_id
        string severity
        string category
        decimal cvss_score
        string status
        string title
        text description
        text recommendation
        string location
        json evidence
        string fingerprint UK
        uuid assigned_to_id FK
        timestamp due_date
        timestamp first_seen_at
        timestamp last_seen_at
        timestamp resolved_at
    }

    cloud_accounts {
        uuid id PK
        uuid organization_id FK
        string provider
        string name
        string auth_type
        string status
        string account_or_subscription_id
        string azure_tenant_id
        string aws_role_arn
        string aws_external_id
        text encrypted_credentials
        string[] monitored_regions
        integer resource_count
        timestamp last_audited_at
    }

    cloud_resources {
        uuid id PK
        uuid organization_id FK
        uuid cloud_account_id FK
        string provider
        string resource_type
        string native_id UK
        string name
        string region
        json configuration
        boolean has_active_findings
    }

    risk_scores {
        uuid id PK
        uuid organization_id FK
        string scope
        uuid asset_id FK
        integer score
        string grade
        integer critical_count
        integer high_count
        integer medium_count
        integer low_count
        json breakdown
        string trigger
        timestamp computed_at
    }

    alerts {
        uuid id PK
        uuid organization_id FK
        uuid asset_id FK
        uuid scan_id FK
        string type
        string severity
        string title
        string message
        json data
        json deliveries
        timestamp acknowledged_at
        timestamp created_at
    }

    reports {
        uuid id PK
        uuid organization_id FK
        uuid asset_id FK
        string type
        uuid generated_by_id FK
        integer score
        string grade
        integer open_findings
        integer pages
        integer size_bytes
        timestamp created_at
    }
```

---

## 2. Catálogo de Tablas y Entidades

### 2.1 Organizaciones y Usuarios
- **`organizations`**: Entidad raíz del modelo multi-tenant. Toda consulta valida `organization_id`. Posee un `verification_token` único de 64 caracteres que el cliente publica en su DNS o archivo web para demostrar control sobre sus dominios.
- **`users`**: Miembros de una organización. Maneja autenticación JWT, factor de costo de hash de contraseña, versión de token (`token_version` para invalidar JWTs activos tras cambio de credenciales) y soporte nativo de TOTP MFA (`mfa_enabled`, `mfa_secret` en Base32).
- **`account_tokens`**: Tokens efímeros enviados por correo electrónico para restablecimiento de contraseña (`PASSWORD_RESET`) e invitaciones a nuevos miembros (`INVITATION`). Se almacena el hash SHA-256 del token para evitar fuga en caso de volcado de base de datos.
- **`audit_log`**: Registro inmutable (*append-only*) de eventos administrativos, de seguridad y cambios de postura, capturando IP de origen, User-Agent y estado previo/posterior.

### 2.2 Inventario de Activos y Superficie Expuesta
- **`assets`**: Dominios (`DOMAIN`), direcciones IP (`IP`) o cuentas cloud vinculadas (`CLOUD_ACCOUNT`). Almacena el estado de verificación de propiedad (`verified_at`, `verification_method`) y criticidad de negocio.
- **`discovered_hosts`**: Subdominios recolectados pasivamente de Certificate Transparency (`crt.sh`). Permite detectar activos colgados o no inventariados (*Shadow IT*) con resolución DNS activa y registro de certificados comodín.

### 2.3 Orquestación, Escaneos y Puertos
- **`diagnostic_batches`**: Registra la ejecución encadenada del Diagnóstico 360° en 3 etapas (`current_stage`, `total_stages`, `status: PENDING | IN_PROGRESS | COMPLETED | FAILED | CANCELLED`). Almacena en `summary` el diff temporal de postura con el lote previo.
- **`scans`**: Trabajos individuales de escaneo (`PORT_SCAN`, `WEB_HEADERS`, `SSL_CERT`, `SENSITIVE_PATHS`, `EMAIL_SECURITY`, `SUBDOMAIN_DISCOVERY`). Funciona como cola de procesamiento asíncrona mediante lectura transaccional `FOR UPDATE SKIP LOCKED`.
- **`scan_ports`**: Servicios de red detectados por Nmap. Desglosa puerto, protocolo, estado, versión de software y CPEs asociados para cruce con CVEs y CISA KEV.

### 2.4 Gestión de Hallazgos y Vulnerabilidades
- **`findings`**: Entidad central de vulnerabilidades y desalineaciones de postura. 
  - **Deduplicación:** Se basa en una clave única compuesta `@@unique([assetId, fingerprint])`, donde `fingerprint = sha256(ruleId + location)`.
  - **Trazabilidad:** Preserva las marcas de tiempo `first_seen_at` y `last_seen_at`. Cuando una vulnerabilidad deja de reproducirse en escaneos posteriores, su estado cambia automáticamente a `RESOLVED` sin duplicar la fila.
  - **SLAs y Triage:** Registra fecha de vencimiento (`due_date`), usuario asignado (`assigned_to_id`), notas de remediación y justificaciones formales de riesgo aceptado.

### 2.5 Seguridad Cloud Multicloud (CSPM)
- **`cloud_accounts`**: Cuentas conectadas de AWS y Azure. Almacena credenciales sensibles (`encrypted_credentials`) cifradas mediante **AES-256-GCM**, IDs de suscripción/cuenta, roles asumibles y regiones monitoreadas.
- **`cloud_resources`**: Recursos descubiertos en la nube (Buckets S3, Máquinas Virtuales EC2/VM, Grupos de Seguridad NSG, Bases de Datos RDS/SQL). Almacena su configuración cruda en JSON para auditoría histórica.

### 2.6 Postura, Alertas y Reportes
- **`risk_scores`**: Instantáneas periódicas o bajo demanda del Security Score (0-100) y Grado (A-F), guardando el desglose matemático ponderado (`breakdown`) para auditorías de cumplimiento.
- **`alerts`** y **`alert_channels`**: Sistema de notificaciones en tiempo real (correo SMTP y webhooks hacia Slack/Discord) con registro del estado de entrega en `deliveries`.
- **`reports`**: Bitácora de reportes ejecutivos y técnicos generados en PDF bajo demanda.
- **`api_keys`**: Credenciales de máquina para integración con SIEM, SOAR y scripts externos.

---

## 3. Estrategias de Rendimiento e Índices

1. **Índices de Multi-Tenancy:** Todas las consultas filtran primariamente por `organization_id`. Se configuraron índices B-Tree compuestos como `@@index([organizationId, status, severity])` para permitir filtros instantáneos (< 20 ms) en el gestor de hallazgos.
2. **Cola de Procesamiento no Bloqueante:**
   El worker reclama escaneos utilizando la consulta:
   ```sql
   SELECT * FROM scans
   WHERE status = 'PENDING'
   ORDER BY created_at ASC
   LIMIT 1
   FOR UPDATE SKIP LOCKED;
   ```
   Esto evita que múltiples réplicas de la API compitan o se bloqueen entre sí.
3. **Integridad Referencial con Eliminación en Cascada:**
   La eliminación de una organización borra de forma limpia y automática en cascada todos sus usuarios, activos, hallazgos, alertas y reportes (`onDelete: Cascade`), evitando registros huérfanos.
