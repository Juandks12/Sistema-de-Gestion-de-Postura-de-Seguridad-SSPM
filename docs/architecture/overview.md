# Visión General de la Arquitectura del Sistema

> **Sistema de Gestión de Postura de Seguridad (SSPM / EASM / CSPM / GRC & Threat Lab)**  
> Versión: **3.0.0 (Sprint 23 — 5 Dominios de Seguridad)**  
> Estado: **Producción / Azure Ready**

Este documento describe la arquitectura global del sistema, su organización modular en **5 Dominios de Seguridad**, la descomposición de componentes C4, los límites de seguridad multi-tenant y el modelo de infraestructura utilizado para desplegar la plataforma.

---

## 1. Principios de Diseño y Arquitectura en 5 Dominios

La plataforma fue diseñada bajo los siguientes principios fundamentales:

1. **Arquitectura Funcional en 5 Dominios Cohesivos:** Todas las vistas de usuario (`AppShell.tsx`) y módulos de backend están estructurados en 5 dominios interconectados:
   - **Dominio 1 — Comando Ejecutivo:** Vista General 360°, Security Score determinista, Quick Wins 24h y Rutas de Ataque (*Kill-Chains*).
   - **Dominio 2 — Superficie y Diagnóstico:** Inventario de Activos, Descubrimiento Certificate Transparency (con promoción 1-clic a 360°), Orquestador de Diagnóstico Profundo 360° y Conectores CSPM Multicloud (AWS & Azure).
   - **Dominio 3 — Laboratorio de Amenazas (`Threat & Malware Lab`):** Estación forense sin ejecución para Correos `.eml` / Cabeceras MIME (BEC, spoofing), Archivos / Hashes (Magic Bytes, entropía de Shannon, macros VBA/XLM, firmas PDF) y URLs sospechosas, con promoción en 1 clic a hallazgo GRC.
   - **Dominio 4 — Centro de Hallazgos y GRC (`GRC Hub`):** Centro Maestro de Hallazgos enriquecido con taxonomía CWE, OWASP Top 10:2021 y MITRE ATT&CK, triaje y SLA en lote, auditoría manual/pentest y evaluación continua sobre 5 marcos normativos (`ISO_27001`, `PCI_DSS`, `SOC_2`, `NIST_CSF`, `CIS_CONTROLS`).
   - **Dominio 5 — Operaciones y Gobierno:** Alertas Tempranas multicanal (SMTP y Webhooks firmados HMAC-SHA256), Reportes PDF Ejecutivos y Técnicos con Matriz GRC y Threat Lab, Monitoreo Continuo (360° + CSPM), API Pública SIEM/SOAR (JSON y NDJSON) y Gobierno RBAC/MFA/Auditoría.
2. **Monorrepo Modular y Cohesivo:** Frontend y backend conviven en un único repositorio con interfaces fuertemente tipadas en TypeScript.
3. **Arquitectura Agentless y Análisis Estático Seguro:** Ningún activo auditado requiere agentes locales, y el análisis de artefactos maliciosos opera de forma 100% estática y heurística en memoria sin ejecutar binarios ni visitar URLs sospechosas.
4. **Desacoplamiento Asíncrono de Procesamiento:** Las tareas intensivas de auditoría (Nmap, sondeos web, escaneo multicloud) se desacoplan de la API REST mediante una cola transaccional en PostgreSQL (`FOR UPDATE SKIP LOCKED`).
5. **Seguridad por Diseño (Secure by Design):** Cifrado en reposo para credenciales cloud (AES-256-GCM), sanitización automática de secretos detectados en código, tokens JWT con versión de revocación, 2FA TOTP, API Keys con hash SHA-256 y bitácora `audit_log` inmutable.

---

## 2. Diagramas C4 del Sistema

### 2.1 C4 Nivel 1: Diagrama de Contexto del Sistema

El siguiente diagrama ilustra los usuarios principales, las fronteras del sistema SSPM y los sistemas externos con los que interactúa:

```mermaid
graph TD
    subgraph "Usuarios y Sistemas Consumidores"
        Admin["Administrador de TI / CISO<br>[Persona]"]
        Analyst["Analista DevSecOps / SOC / Forense<br>[Persona]"]
        Auditor["Auditor GRC / C-Level<br>[Persona]"]
        SIEM_Ext["Plataformas SIEM / SOAR<br>(Splunk, Sentinel, Wazuh, Elastic)"]
    end

    subgraph "Plataforma SSPM (5 Dominios de Seguridad)"
        SSPM_System["Sistema de Gestión de Postura de Seguridad<br>(SSPM / EASM / CSPM / GRC & Threat Lab)<br>Auditoría 360°, Laboratorio de Malware y Gobierno Normativo"]
    end

    subgraph "Sistemas Externos y Perímetro Auditado"
        Target_Ecom["Tiendas E-Commerce, APIs y Servidores<br>[HTTPS / DNS / TLS / TCP]"]
        Cloud_AWS["Amazon Web Services (AWS)<br>[API Cloud SigV4]"]
        Cloud_Azure["Microsoft Azure<br>[Azure ARM REST API]"]
        Threat_Feeds["Inteligencia de Amenazas<br>(CISA KEV / NVD / EPSS / DNSBL)"]
        CT_Logs["Certificate Transparency (crt.sh)<br>[HTTPS API]"]
        Notif_Channels["Canales de Alerta (SMTP / Slack / Discord)<br>[Webhooks HMAC / Email]"]
    end

    Admin -->|"Gestiona tenant, usuarios, canales, API Keys y cuentas cloud"| SSPM_System
    Analyst -->|"Lanza diagnósticos 360°, analiza malware/phishing y gestiona hallazgos"| SSPM_System
    Auditor -->|"Evalúa cumplimiento ISO/PCI/SOC2/NIST/CIS y descarga reportes PDF"| SSPM_System
    SIEM_Ext -->|"Consume /api/v1/public/* (JSON y NDJSON) con X-API-Key"| SSPM_System

    SSPM_System -->|"Audita puertos, cabeceras, Magecart, secretos, DNS y correo"| Target_Ecom
    SSPM_System -->|"Evalúa configuraciones IAM, S3, RDS, EC2, CloudTrail"| Cloud_AWS
    SSPM_System -->|"Evalúa Storage, NSGs, VMs, Azure SQL, Activity Logs"| Cloud_Azure
    SSPM_System -->|"Correlaciona CVEs, KEV, EPSS y reputación de IPs/hashes"| Threat_Feeds
    SSPM_System -->|"Descubre subdominios y los promueve en 1 clic a 360°"| CT_Logs
    SSPM_System -->|"Despacha alertas tempranas firmadas"| Notif_Channels
```

---

### 2.2 C4 Nivel 2: Diagrama de Contenedores

Desglose de los subsistemas y componentes de software desplegables:

```mermaid
graph TD
    subgraph "Navegador Web del Cliente"
        SPA["Frontend SPA (5 Dominios)<br>[React 19 + Vite + Tailwind CSS 4]<br>Comando Ejecutivo, Superficie 360°/CSPM, Threat Lab, GRC Hub y Operaciones"]
    end

    subgraph "Capa de Servidor Perimetral (Ingress)"
        Nginx["Servidor Web Ingress<br>[Nginx Alpine]<br>Sirve estáticos SPA y actúa como Reverse Proxy hacia /api"]
    end

    subgraph "Capa de Backend (NestJS 11 + Node.js 22)"
        API_Gateway["API Gateway & Controllers<br>[NestJS / Express]<br>Validación DTO, Rate Limiting, RBAC y ApiKeyGuard"]
        
        subgraph "Servicios de Negocio Core"
            Auth_Svc["Auth, MFA & Users Service"]
            Assets_Svc["Assets, Verification & CT Discovery"]
            Orch_Svc["Diagnostic 360° Orchestrator & Posture Diff"]
            Worker_Svc["Scan Worker & Monitoring Scheduler"]
            ThreatLab_Svc["Threat & Malware Lab Service<br>(.eml, Archivos/Hashes, URLs)"]
            Findings_Svc["Unified Findings & GRC Taxonomy Service"]
            Compliance_Svc["Multi-Framework Compliance Engine<br>(ISO, PCI, SOC2, NIST, CIS)"]
            Attack_Svc["Attack Paths Correlation Engine"]
            CSPM_Svc["Multicloud CSPM Connectors (AWS & Azure)"]
            Risk_Svc["Deterministic Risk & Score Engine"]
            Reports_Svc["PDFKit Generator (GRC + ThreatLab + 360°)"]
            Alerts_Svc["Alerts, Webhook HMAC & Public SIEM API"]
        end

        subgraph "Analizadores Especializados"
            Nmap_Proc["Nmap Subprocess & CVE/KEV/EPSS"]
            Crawler_Proc["E-Commerce Crawler & Magecart SRI"]
            Secret_Proc["JS Secret Hunter, SourceMap & OpenAPI/GraphQL"]
            TLS_Proc["TLS 1.0–1.3 Probe & X.509 Verifier"]
            DNS_Proc["DNS & Email Security<br>(SPF, DMARC, DKIM, BIMI, CAA, DNSSEC, Wildcard)"]
            Forensic_Proc["Static Malware Analyzers<br>(MIME/BEC, Magic Bytes/Entropy/VBA/PDF, Phishing URL)"]
        end
    end

    subgraph "Capa de Persistencia"
        PostgreSQL[("Base de Datos Relacional<br>[PostgreSQL 16]<br>Esquema multi-tenant, hallazgos GRC, Threat Lab y cola de escaneos")]
    end

    SPA -->|"HTTPS / REST JSON"| Nginx
    Nginx -->|"Proxy Pass /api/v1"| API_Gateway

    API_Gateway --> Auth_Svc & Assets_Svc & Orch_Svc & ThreatLab_Svc & Findings_Svc & Compliance_Svc & Attack_Svc & CSPM_Svc & Risk_Svc & Reports_Svc & Alerts_Svc

    Orch_Svc --> Worker_Svc
    Worker_Svc --> Nmap_Proc & Crawler_Proc & Secret_Proc & TLS_Proc & DNS_Proc
    ThreatLab_Svc --> Forensic_Proc
    ThreatLab_Svc -->|"Promueve IoC"| Findings_Svc
    Findings_Svc <-->|"Sincroniza controles"| Compliance_Svc

    Auth_Svc & Assets_Svc & Orch_Svc & Worker_Svc & ThreatLab_Svc & Findings_Svc & Compliance_Svc & Attack_Svc & CSPM_Svc & Risk_Svc & Reports_Svc & Alerts_Svc -->|"Prisma ORM"| PostgreSQL
```

---

## 3. Modelo de Aislamiento Multi-Tenancy

El sistema garantiza aislamiento lógico de nivel bancario entre organizaciones mediante una estrategia de **Defensa en Profundidad**:

```mermaid
flowchart TD
    Req["Petición HTTP Entrante (Bearer JWT)"] --> JwtGuard["JwtAuthGuard: Valida firma y vigencia del token"]
    JwtGuard --> ExtractPayload["Extrae: userId, organizationId, role"]
    ExtractPayload --> AttachUser["Adjunta UserContext a Request"]
    AttachUser --> RolesGuard["RolesGuard: Verifica permisos RBAC del endpoint"]
    RolesGuard --> Controller["Controlador NestJS"]
    Controller --> Service["Servicio de Negocio"]
    Service --> PrismaClause["Inyección obligatoria: where: { ..., organizationId }"]
    PrismaClause --> DB[(PostgreSQL)]
```

### Reglas de Implementación en Código:
1. **Nunca confiar en IDs de la URL o Body:** Aunque el cliente envíe `assetId: "abc"`, el query a base de datos se formula como:
   ```typescript
   await this.prisma.asset.findFirst({
     where: { id: assetId, organizationId: user.organizationId }
   });
   ```
   Si el activo no pertenece al tenant del usuario autenticado, el resultado es `null`, generando un error `404 Not Found` que evita revelar la existencia de activos de terceros.
2. **Bóveda de Credenciales Seguras (`CryptoVaultService`):**
   Las llaves de API y credenciales de AWS/Azure se cifran con **AES-256-GCM** utilizando una llave maestra derivada del entorno (`APP_VAULT_KEY`). Cada registro posee su propio IV (Initialization Vector) aleatorio de 96 bits y Authentication Tag de 128 bits, impidiendo ataques de texto plano conocido.

---

## 4. Topología de Infraestructura en Producción (Azure)

En entornos de producción sobre Microsoft Azure, la solución se despliega en una arquitectura de alta disponibilidad y bajo mantenimiento operativo:

```mermaid
graph LR
    subgraph "Usuarios en Internet"
        ClientBrowser["Navegadores Clientes"]
    end

    subgraph "Red de Entrega Perimetral (Azure Front Door / CDN)"
        AFD["Azure Front Door + WAF"]
    end

    subgraph "Frontend Layer"
        SWA["Azure Static Web Apps<br>(SPA React 19 / Nginx)"]
    end

    subgraph "Backend Layer (Azure Container Apps)"
        ACA["Container App: Backend API<br>[Autoscaling 1 a 5 réplicas]"]
    end

    subgraph "Data & Secret Management Layer"
        KeyVault["Azure Key Vault<br>[Secretos, Llaves y Certificados]"]
        PostgresFlex["Azure Database for PostgreSQL<br>Flexible Server (v16)<br>[Cifrado en reposo, backups automáticos]"]
    end

    ClientBrowser -->|"HTTPS (Puerto 443)"| AFD
    AFD -->|"Rutas estáticas /*"| SWA
    AFD -->|"Rutas de API /api/*"| ACA
    ACA -->|"Conexión cifrada TLS (Puerto 5432)"| PostgresFlex
    ACA -->|"Managed Identity (OIDC)"| KeyVault
```

### Características de Despliegue:
- **Autoscaling:** Azure Container Apps ajusta el número de réplicas en función del consumo de CPU y la profundidad de la cola de escaneo.
- **Identidad Administrada (Managed Identity):** No se almacenan contraseñas de Azure Key Vault en archivos de configuración ni variables de entorno del repositorio.
- **Cero Downtime:** Actualizaciones mediante despliegues azul/verde (*Blue/Green Deployments*) gestionados automáticamente por GitHub Actions.
