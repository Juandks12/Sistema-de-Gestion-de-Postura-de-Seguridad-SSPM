# Documentación Técnica Integral del Sistema SSPM / EASM / CSPM

> **Sistema de Gestión de Postura de Seguridad (Security Posture Management Platform)**  
> Versión del Sistema: **2.0.0 (Sprint 13)**  
> Fecha de Documentación: **Octubre 2026**  
> Alcance: **Perímetro Externo (EASM), Seguridad E-Commerce / Web Profunda, Postura Cloud Multicloud (CSPM AWS & Azure) y Correlación de Rutas de Ataque (Attack Paths)**

---

## 1. Visión General del Sistema y Objetivos

La **Plataforma de Gestión de Postura de Seguridad (SSPM / EASM / CSPM)** es una solución integral diseñada para proteger a comercios electrónicos, PyMEs y corporativos frente a vectores de ataque modernos. El sistema supera las limitaciones de los escáneres superficiales tradicionales (que solo analizan la raíz HTTP `/` o puertos genéricos) mediante tres capacidades diferenciadoras:

1. **Auditoría E-Commerce y Web Profunda**: Inspección especializada de pasarelas de pago, detección de scripts de terceros sin integridad criptográfica (**Anti-Skimming / Magecart PCI-DSS v4.0**), análisis de bundles JavaScript con búsqueda activa de llaves/secretos (**Secret Hunter**), detección de **Source Maps (`.js.map`)** y auditoría de vulnerabilidades CMS (**WordPress, WooCommerce, PrestaShop, Magento, Shopify**).
2. **Postura de Seguridad Cloud Multicloud (CSPM)**: Conectores nativos sin agente (*agentless*) para **Amazon Web Services (AWS)** y **Microsoft Azure**, auditando configuraciones de IAM, almacenamiento público (S3 / Blob Storage), redes (Security Groups / NSGs), bases de datos y logging contra mejores prácticas CIS Benchmarks.
3. **Orquestación 360° y Correlación de Rutas de Ataque (Attack Paths)**: Diagnóstico integral en 3 etapas encadenadas en 1 clic, motor de **Diff Temporal de Postura** entre escaneos, y un motor de correlación que agrupa hallazgos aislados en **Rutas de Ataque compuestas con narrativa de impacto financiero** y una **Matriz de Priorización Quick Wins 24h (< 30 min) vs. Mejoras Estructurales**.

---

## 2. Matriz de Requerimientos del Sistema

### 2.1 Requerimientos Funcionales (RF)

| ID | Requerimiento Funcional | Módulo Responsable | Descripción y Criterios de Aceptación |
| :--- | :--- | :--- | :--- |
| **RF-01** | **Gestión de Inventario de Activos** | `AssetsModule` | Registro, activación/desactivación, etiquetado y clasificación de criticidad (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) de Dominios, Subdominios e IPs. |
| **RF-02** | **Verificación de Propiedad de Activos** | `AssetsVerification` | Validación de titularidad de dominios antes de escanear mediante registro DNS TXT (`sspm-verification=...`), archivo HTTP en `/.well-known/sspm-verification.txt` o herencia. |
| **RF-03** | **Descubrimiento de Superficie Expuesta (EASM)** | `DiscoveryModule` | Recolección pasiva en registros de Certificate Transparency (crt.sh) para identificar subdominios vivos y alertar ante nuevas apariciones no inventariadas. |
| **RF-04** | **Auditoría de Red, Puertos y Servicios** | `ScansModule` (Nmap/Parser) | Detección no intrusiva de puertos abiertos TCP, identificación de servicios (`serviceName`, `product`, `version`) y correlación con vulnerabilidades conocidas (**CPE / CISA KEV / EPSS**). |
| **RF-05** | **Auditoría de Cabeceras HTTP y TLS** | `ScansModule` (WebHeaders/TLS) | Evaluación de HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, versiones TLS obsoletas (v1.0/v1.1) y fechas de expiración de certificados X.509. |
| **RF-06** | **Seguridad del Correo Electrónico y Marca** | `ScansModule` (EmailSecurity) | Validación de registros SPF (permisividad, número de lookups), DMARC (políticas `none`/`quarantine`/`reject`), DKIM, MTA-STS, TLS-RPT, listas negras DNSBL (Spamhaus/SpamCop) y protección de marca **BIMI** (`default._bimi.<domain>`). |
| **RF-07** | **Escaneo Profundo Web, E-Commerce y Secret Hunter** | `ScansModule` (WebScanners) | Mini-Crawler seguro delimitado (`robots.txt`, `sitemap.xml`, `/checkout`, `/admin`), validación de Subresource Integrity (SRI) en scripts externos, detección de Source Maps `.js.map`, extracción y ofuscación de llaves/secretos de pago en frontend, sondeo activo de CORS Origin Reflection, métodos HTTP peligrosos y auditoría de CMS (XML-RPC, user enumeration). |
| **RF-08** | **Madurez de Divulgación Responsable (RFC 9116)** | `ScansModule` (SecurityTxt) | Inspección de `/.well-known/security.txt` validando directivas obligatorias `Contact:` y fecha de vigencia `Expires:`. |
| **RF-09** | **Auditoría de Postura Cloud Multicloud (CSPM)** | `CloudModule` (AWS & Azure) | Conexión e inventariado sin agente de cuentas AWS (SigV4) y suscripciones Azure (REST API), evaluando reglas CSPM en IAM, Storage (S3/Blobs públicos), Networking, Bases de Datos y CloudTrail/Activity Logs. |
| **RF-10** | **Orquestador de Diagnóstico 360° Encadenado** | `DiagnosticOrchestrator` | Ejecución multi-etapa en 1 clic: **Etapa 1** (Descubrimiento EASM) → **Etapa 2** (Red, TLS y Correo) → **Etapa 3** (Web Profunda, E-Commerce y Rutas), con barra de progreso reactiva y cancelación en cascada. |
| **RF-11** | **Motor de Diff Temporal de Postura** | `DiagnosticOrchestrator` | Comparación automatizada entre diagnósticos sucesivos: delta de Security Score, hallazgos remediados vs. nuevas regresiones y balance de variación en puertos y tecnologías. |
| **RF-12** | **Correlación de Rutas de Ataque (Attack Paths)** | `FindingsModule` (AttackPaths) | Algoritmo que encadena vulnerabilidades aisladas en 6 escenarios de riesgo de negocio (Fraude en Pagos Magecart, Toma de Control de Tienda, Suplantación de Marca BEC, Exfiltración de Datos, Compromiso de Infraestructura, Subdomain Takeover) con narrativa de impacto comercial y pasos kill-chain. |
| **RF-13** | **Matriz Quick Wins 24h vs. Mejoras Estructurales** | `FindingsModule` (RulesCatalog) | Clasificación de esfuerzo de remediación (`QUICK_WIN` < 30 min, `MODERATE` < 2 h, `STRUCTURAL` > 4 h), tiempos estimados y filtrado por un clic en la interfaz. |
| **RF-14** | **Gestión de Hallazgos, SLAs y Triage Inteligente** | `FindingsModule` | Trazabilidad del ciclo de vida (`OPEN`, `IN_PROGRESS`, `VERIFYING`, `RESOLVED`, `ACCEPTED`, `FALSE_POSITIVE`), asignación de responsables, cálculo de vencimiento según SLAs por severidad, re-test puntual y asistencia de triage heurístico/IA. |
| **RF-15** | **Motor de Riesgo y Security Score Determinista** | `RiskModule` | Cálculo matemático transparente (0-100, grados A-F) sin cajas negras, con penalizaciones ponderadas por severidad (`CRITICAL`: 25, `HIGH`: 15, `MEDIUM`: 6, `LOW`: 2) y topes máximos para evitar puntuaciones infladas. |
| **RF-16** | **Reportes Ejecutivos y Técnicos en PDF** | `ReportsModule` (PDFRenderer) | Generación de reportes bajo demanda o programados: Reporte Ejecutivo con diagnóstico en lenguaje de negocio, Rutas de Ataque, Impacto Financiero y Matriz Quick Wins 24h; Reporte Técnico con detalles de puertos, ciphers y evidencias forenses. |
| **RF-17** | **Alertas Tempranas y Webhooks** | `AlertsModule` | Disparo en tiempo real de notificaciones ante puertos recién abiertos, certificados por expirar (< 7 días), hallazgos críticos o caídas de score, despachadas vía Email (SMTP) o Webhook (Slack, Discord, JSON genérico) con control de concurrencia y reintentos. |
| **RF-18** | **Monitoreo Continuo Automatizado** | `MonitoringModule` | Programador configurable (Diario / Semanal / Desactivado) que encola y ejecuta escaneos periódicos sin intervención humana. |

---

### 2.2 Requerimientos No Funcionales (RNF)

| ID | Requerimiento No Funcional | Especificación Técnica |
| :--- | :--- | :--- |
| **RNF-01** | **Seguridad Multi-Tenancy Estricta** | Aislamiento lógico riguroso por `organizationId` validado en cada query a base de datos. Ninguna petición puede acceder a datos de otra organización. |
| **RNF-02** | **Autenticación Fuerte y MFA** | Tokens JWT con expiración corta (15 min), Refresh Tokens seguros, hashing de contraseñas con Argon2id/Bcrypt y soporte nativo de autenticación de dos factores (TOTP RFC 6238). |
| **RNF-03** | **Control de Acceso Basado en Roles (RBAC)** | Roles predefinidos (`ADMIN`, `ANALYST`, `VIEWER`) aplicados mediante decoradores `@Roles()` en NestJS y guards de ruta en React. |
| **RNF-04** | **Escaneo No Intrusivo y Seguro** | Todos los sondeos web, DNS y de red operan de forma no destructiva (sin inyección SQL, sin payloads destructivos de exploits, con límites de timeout de 10s y respeto de `robots.txt`). |
| **RNF-05** | **Determinismo y Transparencia del Scoring** | El algoritmo de Security Score es 100% determinista y auditable; dos organizaciones con la misma composición de hallazgos obtienen exactamente la misma calificación. |
| **RNF-06** | **Trazabilidad y Auditoría de Operaciones** | Registro inmutable en tabla `audit_logs` de todas las acciones administrativas (creación/edición de usuarios, aceptación de riesgos, cambios de estado en hallazgos y generación de reportes). |
| **RNF-07** | **Rendimiento y Control de Concurrencia** | Cola de escaneo transaccional en PostgreSQL (`FOR UPDATE SKIP LOCKED`) con ajuste adaptativo de concurrencia para evitar saturación de CPU o ancho de banda. |
| **RNF-08** | **Privacidad y Ofuscación de Secretos** | Cualquier token, llave de API o secreto detectado por el analizador es automáticamente ofuscado (`redactToken`: ej. `sk_live_...4a2b`) antes de almacenarse en base de datos. |
| **RNF-09** | **Compatibilidad y Estándares Abiertos** | Formatos estándar RFC 4180 (CSV con BOM UTF-8), RFC 9116 (`security.txt`), BIMI, PDF-1.4 (WinAnsi Latin-1 seguro) y Swagger/OpenAPI v3. |
| **RNF-10** | **Retención de Datos y Purga Automática** | Mecanismo programado de purga para escaneos antiguos, logs de auditoría históricos y tokens de sesión expirados (`RetentionService`). |

---

## 3. Arquitectura del Sistema (C4 Nivel 1 y Nivel 2)

El sistema se compone de una arquitectura modular basada en microservicios lógicos encapsulados en un monorrepo limpio, desplegable mediante contenedores Docker en Azure (Container Apps para API, Static Web Apps para Frontend y PostgreSQL administrado).

```mermaid
graph TD
    subgraph "Usuarios y Roles"
        U_Admin["Administrador de Seguridad"]
        U_Analyst["Analista SOC / DevSecOps"]
        U_Exec["Dueño de Comercio / C-Level (Viewer)"]
    end

    subgraph "Frontend Layer (React 19 + Vite + Tailwind)"
        UI_Dash["Dashboard & KPIs"]
        UI_Findings["Gestor de Hallazgos & Quick Wins"]
        UI_AttackPaths["Visor Interactivo de Attack Paths"]
        UI_360["Stepper Diagnóstico 360°"]
        UI_CSPM["Consola de Seguridad Cloud"]
    end

    subgraph "API Gateway & Security (NestJS)"
        GW_Auth["JWT & RBAC Guard"]
        GW_RateLimit["Rate Limiting & Anti-BruteForce"]
        GW_Audit["Interceptor de Auditoría"]
    end

    subgraph "Backend Core Services (NestJS Modules)"
        MOD_Assets["Assets & Ownership Service"]
        MOD_Scans["Scan Worker & Engine"]
        MOD_Orch["Diagnostic 360° Orchestrator"]
        MOD_AttackPaths["Attack Paths Correlation Engine"]
        MOD_CSPM["Multicloud CSPM Connectors (AWS/Azure)"]
        MOD_Risk["Risk Scoring & SLA Engine"]
        MOD_Reports["PDF Reports Generator"]
        MOD_Alerts["Alerts & Webhook Dispatcher"]
    end

    subgraph "Almacenamiento y Colas (PostgreSQL 16)"
        DB_Core[("PostgreSQL Multi-Tenant")]
        DB_Queue[("Cola Transaccional Scans")]
    end

    subgraph "Servicios Externos y Perímetro Auditado"
        EXT_TargetWeb["Tienda E-Commerce / APIs"]
        EXT_DNS["Servidores DNS (SPF/DMARC/BIMI)"]
        EXT_CloudAWS["AWS API (STS / IAM / S3 / EC2)"]
        EXT_CloudAzure["Azure Resource Manager API"]
        EXT_ThreatIntel["CISA KEV / FIRST EPSS / NVD"]
        EXT_Notif["SMTP / Slack / Discord Webhooks"]
    end

    U_Admin --> UI_Dash
    U_Analyst --> UI_Findings
    U_Exec --> UI_AttackPaths

    UI_Dash --> GW_Auth
    UI_Findings --> GW_Auth
    UI_AttackPaths --> GW_Auth
    UI_360 --> GW_Auth
    UI_CSPM --> GW_Auth

    GW_Auth --> GW_RateLimit --> GW_Audit

    GW_Audit --> MOD_Assets
    GW_Audit --> MOD_Scans
    GW_Audit --> MOD_Orch
    GW_Audit --> MOD_AttackPaths
    GW_Audit --> MOD_CSPM
    GW_Audit --> MOD_Risk
    GW_Audit --> MOD_Reports
    GW_Audit --> MOD_Alerts

    MOD_Assets --> DB_Core
    MOD_Scans --> DB_Queue
    MOD_Orch --> MOD_Scans
    MOD_AttackPaths --> DB_Core
    MOD_CSPM --> EXT_CloudAWS
    MOD_CSPM --> EXT_CloudAzure
    MOD_Scans --> EXT_TargetWeb
    MOD_Scans --> EXT_DNS
    MOD_Scans --> EXT_ThreatIntel
    MOD_Alerts --> EXT_Notif
    MOD_Reports --> DB_Core
```

---

## 4. Diagramas de Flujos y Procesos Clave

### 4.1 Flujo del Orquestador de Diagnóstico 360° en 3 Etapas

Este flujo ejecuta el diagnóstico integral multi-etapa en un solo clic, asegurando progresión ordenada y consolidación de postura:

```mermaid
sequenceDiagram
    autonumber
    actor Usuario as Analista / Comercio
    participant UI as Frontend (Diagnostic360Stepper)
    participant Orch as DiagnosticOrchestratorService
    participant Queue as Cola PostgreSQL (scans)
    participant Worker as ScanWorkerService
    participant Analyzers as Analizadores Especializados
    participant Diff as PostureDiffService

    Usuario->>UI: Clic en "Iniciar Diagnóstico 360°"
    UI->>Orch: POST /api/v1/assets/:id/diagnostic-360
    Orch->>Orch: Crear registro DiagnosticBatch (status: RUNNING, stage: 1)
    
    rect rgb(240, 248, 255)
        note over Orch,Worker: ETAPA 1: Descubrimiento de Superficie (EASM)
        Orch->>Queue: Encolar SUBDOMAIN_DISCOVERY (batchId, stage: 1)
        Worker->>Queue: Reclamar escaneo (FOR UPDATE SKIP LOCKED)
        Worker->>Analyzers: Consultar crt.sh y resolver registros DNS
        Analyzers-->>Worker: Subdominios vivos detectados
        Worker->>Orch: Notificar escaneo completado (Etapa 1 OK)
    end

    rect rgb(245, 255, 245)
        note over Orch,Worker: ETAPA 2: Perímetro, Red y Correo
        Orch->>Orch: Actualizar batch (stage: 2)
        Orch->>Queue: Encolar PORT_SCAN, SSL_CERT, EMAIL_SECURITY (stage: 2)
        Worker->>Analyzers: Ejecutar Nmap, probe TLS, SPF/DMARC/DKIM/BIMI
        Analyzers-->>Worker: Puertos abiertos, ciphers y estado de correo
        Worker->>Orch: Notificar escaneos completados (Etapa 2 OK)
    end

    rect rgb(255, 250, 240)
        note over Orch,Worker: ETAPA 3: Web Profunda, E-Commerce y Secret Hunter
        Orch->>Orch: Actualizar batch (stage: 3)
        Orch->>Queue: Encolar WEB_HEADERS y SENSITIVE_PATHS (stage: 3)
        Worker->>Analyzers: Mini-Crawler checkout, SRI Magecart, JS Secrets, security.txt
        Analyzers-->>Worker: Hallazgos de e-commerce y secretos frontend
        Worker->>Orch: Notificar escaneos completados (Etapa 3 OK)
    end

    Orch->>Diff: Calcular Posture Diff vs. Lote Anterior
    Diff-->>Orch: Delta Score (+X pts), remediados (N), regresiones (M)
    Orch->>Orch: Marcar DiagnosticBatch (status: COMPLETED)
    UI->>Orch: Polling reactivo / WebSocket
    Orch-->>UI: Lote completado + Datos de Posture Diff
    UI-->>Usuario: Mostrar resumen 360° y botón de comparación
```

---

### 4.2 Flujo del Motor de Correlación de Rutas de Ataque (Attack Paths & Kill Chain)

Transforma hallazgos atómicos en escenarios de impacto para el negocio:

```mermaid
flowchart TD
    Start(["Inicio: Analizar Hallazgos Abiertos de la Organización"]) --> QueryFindings["Consultar Findings en estado OPEN, IN_PROGRESS, VERIFYING"]
    QueryFindings --> GroupAssets["Agrupar hallazgos por activo objetivo"]

    subgraph Correlacion ["Evaluadores de Rutas de Ataque"]
        E1{"¿Scripts sin SRI + CSP ausente + Formulario HTTP?"}
        E2{"¿Login expuesto + WP Enumeration + XMLRPC?"}
        E3{"¿DMARC ausente/p=none + SPF permisivo?"}
        E4{"¿Sourcemaps/.env expuesto + CORS reflejado?"}
        E5{"¿Puertos DB/SSH expuestos + CVEs CISA KEV?"}
        E6{"¿CNAME huérfano a proveedor Cloud?"}
    end

    GroupAssets --> E1
    GroupAssets --> E2
    GroupAssets --> E3
    GroupAssets --> E4
    GroupAssets --> E5
    GroupAssets --> E6

    E1 -- Sí --> AP1["AP-PAYMENT-FRAUD<br>Fraude en Pasarela & E-Skimming<br>Severidad: CRITICAL (PCI-DSS v4.0)"]
    E2 -- Sí --> AP2["AP-STORE-TAKEOVER<br>Toma de Control de Tienda Online<br>Severidad: CRITICAL"]
    E3 -- Sí --> AP3["AP-BRAND-IMPERSONATION<br>Suplantación de Marca y Fraude Facturero<br>Severidad: HIGH (BEC / Phishing)"]
    E4 -- Sí --> AP4["AP-DATA-EXFILTRATION<br>Exfiltración de Código y Datos Clientes<br>Severidad: CRITICAL"]
    E5 -- Sí --> AP5["AP-INFRASTRUCTURE-COMPROMISE<br>Compromiso Perimetral y Ransomware<br>Severidad: CRITICAL"]
    E6 -- Sí --> AP6["AP-SUBDOMAIN-TAKEOVER<br>Secuestro de Subdominio de Comercio<br>Severidad: HIGH"]

    AP1 & AP2 & AP3 & AP4 & AP5 & AP6 --> BuildKillChain["Construir Kill Chain de 3 Pasos:<br>1. Vector de Acceso<br>2. Explotación/Evasión<br>3. Impacto en Negocio"]
    BuildKillChain --> MatchQuickWins["Cruzar con Catálogo de Reglas y contabilizar Quick Wins (< 30 min)"]
    MatchQuickWins --> SortSeverity["Ordenar Rutas: CRITICAL > HIGH > MEDIUM"]
    SortSeverity --> ReturnSummary(["Retornar AttackPathSummary[] a API y Reportes PDF"])
```

---

### 4.3 Flujo de Escaneo de Postura Cloud Multicloud (CSPM AWS & Azure)

```mermaid
sequenceDiagram
    autonumber
    actor DevSecOps as Analista de Seguridad
    participant UI as Consola Cloud (CSPM)
    participant CloudService as CloudScanService
    participant AWSConn as AwsConnectorService
    participant AzureConn as AzureConnectorService
    participant Evaluator as CSPM Evaluator
    participant Findings as FindingsService

    DevSecOps->>UI: Solicitar Escaneo Cloud (AWS o Azure)
    UI->>CloudService: POST /api/v1/cloud/accounts/:id/scan
    
    alt Proveedor: Amazon Web Services (AWS)
        CloudService->>AWSConn: Obtener credenciales seguras (CryptoVault)
        AWSConn->>AWSConn: Firmar peticiones con AWS SigV4
        AWSConn->>AWSConn: Consultar IAM (MFA root, credenciales 90d)
        AWSConn->>AWSConn: Consultar S3 (Block Public Access, cifrado)
        AWSConn->>AWSConn: Consultar EC2/Security Groups (puertos 22/3389 0.0.0.0/0)
        AWSConn->>AWSConn: Consultar RDS (almacenamiento cifrado, acceso público)
        AWSConn->>AWSConn: Consultar CloudTrail (multi-región, validación de logs)
        AWSConn-->>CloudService: Recursos e inventario normalizado
    else Proveedor: Microsoft Azure
        CloudService->>AzureConn: Obtener Client Secret/Certificado
        AzureConn->>AzureConn: Autenticación OAuth2 contra Azure AD
        AzureConn->>AzureConn: Consultar Microsoft.Storage (cuentas públicas)
        AzureConn->>AzureConn: Consultar Network Security Groups (reglas inbound)
        AzureConn->>AzureConn: Consultar Azure SQL (TDE, firewall)
        AzureConn->>AzureConn: Consultar Azure Activity Logs / Monitor
        AzureConn-->>CloudService: Recursos e inventario normalizado
    end

    CloudService->>Evaluator: Evaluar Inventario contra Reglas CSPM
    Evaluator->>Findings: Generar o actualizar Findings (Categorías CLOUD_*)
    Findings-->>UI: Hallazgos CSPM consolidados con Remediation Guides
    UI-->>DevSecOps: Dashboard Cloud actualizado
```

---

### 4.4 Ciclo de Vida del Hallazgo y Gestión de SLAs

```mermaid
stateDiagram-v2
    [*] --> OPEN: Hallazgo detectado por Escáner
    OPEN --> IN_PROGRESS: Asignado a líder técnico / Inicio de mitigación
    IN_PROGRESS --> VERIFYING: Fix aplicado en servidor
    
    VERIFYING --> RESOLVED: Re-test puntual exitoso (ya no reproduce)
    VERIFYING --> IN_PROGRESS: Re-test fallido (vulnerabilidad persiste)
    
    OPEN --> ACCEPTED: Aceptación formal del riesgo justificada
    OPEN --> FALSE_POSITIVE: Triage confirma regla inaplicable / WAF mitigante
    
    ACCEPTED --> OPEN: Revisión periódica de riesgo revoca aceptación
    FALSE_POSITIVE --> OPEN: Reabierto por analista
    
    RESOLVED --> OPEN: Detección recurrente en escaneo programado (Regresión)
    
    state OPEN {
        [*] --> ON_TRACK
        ON_TRACK --> APPROACHING: Faltan < 48h para SLA
        APPROACHING --> OVERDUE: Fecha límite superada
    }
```

---

### 4.5 Algoritmo Determinista del Security Score

```mermaid
flowchart LR
    subgraph Inputs ["Conteo de Hallazgos Abiertos"]
        C["Críticos (N_crit)"]
        H["Altos (N_high)"]
        M["Medios (N_med)"]
        L["Bajos (N_low)"]
    end

    subgraph CalculoPuntos ["Penalizaciones Ponderadas"]
        P_C["N_crit × 25 pts (Tope: 60)"]
        P_H["N_high × 15 pts (Tope: 45)"]
        P_M["N_med × 6 pts (Tope: 30)"]
        P_L["N_low × 2 pts (Tope: 15)"]
    end

    C --> P_C
    H --> P_H
    M --> P_M
    L --> P_L

    subgraph Formula ["Fórmula Matemática"]
        Calc["Pérdida Total = min(100, P_C + P_H + P_M + P_L)<br>Score = max(0, 100 - Pérdida Total)"]
    end

    P_C & P_H & P_M & P_L --> Calc

    subgraph Bandas ["Bandas de Calificación (Grados)"]
        A["Grado A: 90 - 100 (Excelente)"]
        B["Grado B: 80 - 89 (Bueno)"]
        C_Grade["Grado C: 70 - 79 (Aceptable)"]
        D["Grado D: 60 - 69 (Deficiente)"]
        F["Grado F: 0 - 59 (Crítico)"]
    end

    Calc --> A & B & C_Grade & D & F
```

---

## 5. Modelo de Datos y Esquema de Base de Datos (ERD)

```mermaid
erDiagram
    organizations ||--o{ users : "tiene"
    organizations ||--o{ assets : "posee"
    organizations ||--o{ cloud_accounts : "conecta"
    organizations ||--o{ alerts : "genera"
    organizations ||--o{ alert_channels : "configura"
    organizations ||--o{ reports : "emite"
    organizations ||--o{ audit_logs : "registra"

    assets ||--o{ scans : "ejecuta"
    assets ||--o{ diagnostic_batches : "orquesta"
    assets ||--o{ findings : "presenta"
    assets ||--o{ asset_verifications : "valida"

    cloud_accounts ||--o{ cloud_resources : "descubre"
    cloud_resources ||--o{ findings : "asocia"

    scans ||--o{ scan_ports : "detecta"
    scans }o--|| diagnostic_batches : "pertenece"

    users ||--o{ findings : "asignado_a"
    users ||--o{ reports : "generado_por"
    users ||--o{ audit_logs : "actua_en"

    organizations {
        uuid id PK
        string name
        string slug
        string monitoring_frequency
        timestamp created_at
    }

    assets {
        uuid id PK
        uuid organization_id FK
        string type
        string value
        string name
        string criticality
        boolean is_active
        boolean authorization_confirmed
        timestamp verified_at
    }

    cloud_accounts {
        uuid id PK
        uuid organization_id FK
        string provider
        string name
        string account_or_subscription_id
        timestamp last_synced_at
    }

    diagnostic_batches {
        uuid id PK
        uuid asset_id FK
        string status
        integer current_stage
        integer total_stages
        json posture_diff
        timestamp started_at
        timestamp completed_at
    }

    scans {
        uuid id PK
        uuid asset_id FK
        uuid batch_id FK
        string type
        string status
        integer stage
        json summary
        timestamp started_at
        timestamp finished_at
    }

    findings {
        uuid id PK
        uuid organization_id FK
        uuid asset_id FK
        uuid cloud_resource_id FK
        string rule_id
        string severity
        string category
        string status
        string title
        text description
        text recommendation
        string location
        string effort_level
        integer estimated_minutes
        text business_impact
        uuid assigned_to_id FK
        timestamp due_date
        timestamp first_seen_at
        timestamp last_seen_at
    }
```

---

## 6. Detalle Modular del Sistema

### 6.1 Módulo de Escaneo y Web Profunda (`backend/src/scans/`)
- **`ecommerce-crawler.ts`**: Crawler con límite estricto de páginas y dominios que extrae selectores de formularios, campos de contraseñas/tarjetas y analiza scripts externos.
- **`magecart-security.analyzer.ts`**: Validador de PCI-DSS v4.0 Req. 6.4.3 (hashes SRI obligatorios) y Req. 11.6.1 (integridad de cabeceras y ausencia de mixed-content).
- **`js-secrets-sourcemap.analyzer.ts`**: Búsqueda regex de alto rendimiento para llaves Stripe (`sk_live_`), MercadoPago (`APP_USR-`), tokens AWS, llaves JWT y accesibilidad de mapas `.js.map`.
- **`cms-ecommerce.analyzer.ts`**: Pruebas activas contra `/wp-json/wp/v2/users`, `/xmlrpc.php`, `debug.log`, paneles de login expuestos e introspección GraphQL.
- **`security-txt.analyzer.ts`**: Analizador RFC 9116 validando `Contact:` y `Expires:`.
- **`bimi.ts`**: Consultas DNS TXT a `default._bimi.<domain>` para verificar logotipos SVG de marca.

### 6.2 Módulo de Correlación de Rutas de Ataque (`backend/src/findings/attack-paths.service.ts`)
- Agrupa hallazgos en escenarios de amenaza concretos con cálculo dinámico de `quickWinsAvailable` y acciones de mitigación recomendadas.

### 6.3 Módulo CSPM Multicloud (`backend/src/cloud/`)
- **`aws-connector.service.ts`**: Llamadas REST firmadas con SigV4 usando llaves cifradas con AES-256-GCM desde `CryptoVaultService`.
- **`azure-connector.service.ts`**: Conexión vía Service Principal con Azure REST API.
- **`cspm.catalog.ts`**: Reglas de postura en IAM, Compute, Redes, Almacenamiento y Logging.

### 6.4 Módulo de Riesgo y Security Score (`backend/src/risk/scoring.ts`)
- Modelo matemático determinista con topes por categoría y penalizaciones balanceadas.

### 6.5 Generador de Reportes PDF (`backend/src/reports/pdf-renderer.ts`)
- Renderizado de PDF con PDFKit en memoria, WinAnsi seguro, paleta cromática profesional y bloques para C-Levels y equipos técnicos.

---

## 7. Políticas de Seguridad y Despliegue en Producción

1. **Gestión de Secretos**: Todas las credenciales maestras y llaves de cifrado se cargan desde variables de entorno y Azure Key Vault. En base de datos, los secretos de conectores Cloud se cifran con **AES-256-GCM** con vector de inicialización único por registro.
2. **Pipelines de Integración Continua (CI/CD)**:
   - Verificación obligatoria en cada Pull Request: análisis estático ESLint (0 errores), tipado TypeScript estricto, 81 suites de pruebas unitarias/e2e y verificación de autoría de commits.
   - Despliegue automatizado con autenticación federada OIDC (GitHub Actions a Azure Container Apps y Static Web Apps sin almacenar secretos en el repositorio).
