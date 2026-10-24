# Visión General de la Arquitectura del Sistema

> **Sistema de Gestión de Postura de Seguridad (SSPM / EASM / CSPM)**  
> Versión: **2.0.0 (Sprint 13)**  
> Estado: **Producción / Azure Ready**

Este documento describe la arquitectura global del sistema, la descomposición de componentes, los límites de seguridad y el modelo de infraestructura utilizado para desplegar la plataforma.

---

## 1. Principios de Diseño y Filosofía Arquitectónica

La plataforma fue diseñada bajo los siguientes principios fundamentales:

1. **Monorrepo Modular y Cohesivo:** Frontend y backend conviven en un único repositorio con interfaces fuertemente tipadas en TypeScript, facilitando el versionado sincronizado, refactorizaciones seguras y pipelines de integración unificados.
2. **Arquitectura Agentless (Sin Agentes):** Ningún cliente o servidor auditado requiere instalar binarios propietarios o agentes residentes en sus sistemas. Toda la auditoría se efectúa mediante protocolos de red abiertos (HTTP, TLS, DNS, TCP) o APIs nativas de nube (AWS REST con SigV4, Azure ARM).
3. **Desacoplamiento Asíncrono de Procesamiento:** Las tareas intensivas de auditoría (Nmap, sondeos web, escaneo multicloud) se desacoplan de la API REST mediante una cola transaccional en base de datos, garantizando tiempos de respuesta inmediatos (< 50 ms) para los usuarios web.
4. **Seguridad por Diseño (Secure by Design):** Cifrado en reposo para credenciales de terceros (AES-256-GCM), sanitización automática de secretos detectados en código, tokens JWT de expiración corta, verificación de dos factores (TOTP) y registros de auditoría append-only.

---

## 2. Diagramas C4 del Sistema

### 2.1 C4 Nivel 1: Diagrama de Contexto del Sistema

El siguiente diagrama ilustra los usuarios principales, las fronteras del sistema SSPM y los sistemas externos con los que interactúa:

```mermaid
graph TD
    subgraph "Usuarios de la Plataforma"
        Admin["Administrador de TI / CISO<br>[Persona]"]
        Analyst["Analista DevSecOps / SOC<br>[Persona]"]
        Auditor["Auditor Externo / C-Level<br>[Persona]"]
    end

    subgraph "Plataforma SSPM"
        SSPM_System["Sistema de Gestión de Postura de Seguridad (SSPM)<br>[Software System]<br>Plataforma SaaS para auditoría perimetral, e-commerce y cloud"]
    end

    subgraph "Sistemas Externos y Perímetro Auditado"
        Target_Ecom["Tiendas E-Commerce y Aplicaciones Web<br>[HTTPS / DNS / TLS]"]
        Cloud_AWS["Amazon Web Services (AWS)<br>[API Cloud]"]
        Cloud_Azure["Microsoft Azure<br>[API Cloud]"]
        Threat_Feeds["Bases de Amenazas (CISA KEV / NVD)<br>[HTTPS REST]"]
        CT_Logs["Logs de Certificate Transparency (crt.sh)<br>[HTTPS API]"]
        Notif_Channels["Canales de Alerta (SMTP / Slack / Discord)<br>[Webhooks / Email]"]
    end

    Admin -->|"Gestiona tenant, usuarios y cuentas cloud"| SSPM_System
    Analyst -->|"Lanza diagnósticos 360°, remedia y re-testea"| SSPM_System
    Auditor -->|"Descarga reportes ejecutivos en PDF y revisa SLAs"| SSPM_System

    SSPM_System -->|"Audita puertos, cabeceras, Magecart y secretos"| Target_Ecom
    SSPM_System -->|"Evalúa configuraciones IAM, S3, RDS, CloudTrail"| Cloud_AWS
    SSPM_System -->|"Evalúa almacenamiento, NSGs, SQL, Activity Logs"| Cloud_Azure
    SSPM_System -->|"Consulta vulnerabilidades explotadas conocidas"| Threat_Feeds
    SSPM_System -->|"Descubre subdominios vivos no inventariados"| CT_Logs
    SSPM_System -->|"Despacha alertas tempranas de riesgo"| Notif_Channels
```

---

### 2.2 C4 Nivel 2: Diagrama de Contenedores

Desglose de los subsistemas y componentes de software desplegables:

```mermaid
graph TD
    subgraph "Navegador Web del Cliente"
        SPA["Frontend SPA<br>[React 19 + Vite + Tailwind CSS 4]<br>Dashboard reactivo, Stepper 360°, Matriz Quick Wins"]
    end

    subgraph "Capa de Servidor Perimetral (Ingress)"
        Nginx["Servidor Web Ingress<br>[Nginx Alpine]<br>Sirve estáticos SPA y actúa como Reverse Proxy hacia /api"]
    end

    subgraph "Capa de Backend (NestJS 11 + Node.js 22)"
        API_Gateway["API Gateway & Controllers<br>[NestJS / Express]<br>Validación DTO, Rate Limiting, RBAC"]
        
        subgraph "Servicios de Negocio"
            Auth_Svc["Auth & MFA Service"]
            Assets_Svc["Assets & Verification Service"]
            Orch_Svc["Diagnostic 360° Orchestrator"]
            Worker_Svc["Scan Worker Engine"]
            Attack_Svc["Attack Paths Correlation Engine"]
            CSPM_Svc["Multicloud CSPM Connectors"]
            Risk_Svc["Deterministic Risk & Score Engine"]
            Reports_Svc["PDFKit Reports Generator"]
            Alerts_Svc["Alerts & Webhook Dispatcher"]
        end

        subgraph "Analizadores Especializados"
            Nmap_Proc["Nmap Subprocess Executor"]
            Crawler_Proc["Mini-Crawler & Magecart SRI Analyzer"]
            Secret_Proc["JS Secret Hunter & SourceMap Sonda"]
            TLS_Proc["TLS 1.0/1.1 Probe & X.509 Verifier"]
            DNS_Proc["Email Security (SPF/DMARC/BIMI)"]
        end
    end

    subgraph "Capa de Persistencia"
        PostgreSQL[("Base de Datos Relacional<br>[PostgreSQL 16]<br>Esquema multi-tenant, auditoría y cola de escaneos")]
    end

    SPA -->|"HTTPS / REST JSON"| Nginx
    Nginx -->|"Proxy Pass /api/v1"| API_Gateway

    API_Gateway --> Auth_Svc
    API_Gateway --> Assets_Svc
    API_Gateway --> Orch_Svc
    API_Gateway --> Attack_Svc
    API_Gateway --> CSPM_Svc
    API_Gateway --> Risk_Svc
    API_Gateway --> Reports_Svc
    API_Gateway --> Alerts_Svc

    Orch_Svc --> Worker_Svc
    Worker_Svc --> Nmap_Proc
    Worker_Svc --> Crawler_Proc
    Worker_Svc --> Secret_Proc
    Worker_Svc --> TLS_Proc
    Worker_Svc --> DNS_Proc

    Auth_Svc & Assets_Svc & Orch_Svc & Worker_Svc & Attack_Svc & CSPM_Svc & Risk_Svc & Reports_Svc & Alerts_Svc -->|"Prisma ORM (Conexiones Agrupadas)"| PostgreSQL
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
