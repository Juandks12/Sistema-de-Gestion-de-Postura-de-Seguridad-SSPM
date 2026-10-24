# Flujos de Trabajo y Diagramas de Secuencia

> **Sistema de Gestión de Postura de Seguridad (SSPM / EASM / CSPM)**  
> Versión: **2.0.0**  
> Alcance: **Flujos Críticos del Sistema en Mermaid**

Este documento recopila la especificación técnica y los diagramas de secuencia/flujo de los 5 procesos centrales de la plataforma.

---

## Índice de Flujos de Trabajo

1. [Flujo 1: Orquestador de Diagnóstico 360° en 3 Etapas](#1-flujo-del-orquestador-de-diagnóstico-360-en-3-etapas)
2. [Flujo 2: Motor de Correlación de Rutas de Ataque (Attack Paths & Kill Chain)](#2-flujo-del-motor-de-correlación-de-rutas-de-ataque-attack-paths)
3. [Flujo 3: Escaneo de Postura Cloud Multicloud (CSPM AWS & Azure)](#3-flujo-de-escaneo-de-postura-cloud-multicloud-cspm-aws--azure)
4. [Flujo 4: Ciclo de Vida del Hallazgo y Gestión de SLAs](#4-flujo-del-ciclo-de-vida-del-hallazgo-y-gestión-de-slas)
5. [Flujo 5: Algoritmo Determinista del Security Score](#5-flujo-del-algoritmo-determinista-del-security-score)

---

## 1. Flujo del Orquestador de Diagnóstico 360° en 3 Etapas

El diagnóstico 360° orquesta la ejecución secuencial ordenada de múltiples tipos de escáner en un solo clic, garantizando que el descubrimiento de subdominios alimente las etapas posteriores y calculando al finalizar el diferencial de postura con el lote anterior.

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

### Mecanismos de Tolerancia a Fallos del Orquestador:
- **Cancelación en Cascada:** Si el usuario aborta el diagnóstico en la Etapa 2, todos los escaneos pendientes en la base de datos pertenecientes al `batchId` pasan automáticamente al estado `CANCELLED`.
- **Aislamiento de Etapa:** El fallo aislado de un analizador (por ejemplo, timeout en la consulta a `crt.sh`) no detiene el avance hacia la Etapa 2; el error se registra en el sumario y el proceso continúa.

---

## 2. Flujo del Motor de Correlación de Rutas de Ataque (Attack Paths)

Este flujo transforma los hallazgos individuales (que a menudo saturan a los equipos técnicos) en **escenarios de riesgo de negocio compuestos**, dotando a los directivos de contexto sobre el impacto financiero real.

```mermaid
flowchart TD
    Start(["Inicio: Analizar Hallazgos Abiertos de la Organización"]) --> QueryFindings["Consultar Findings en estado OPEN, IN_PROGRESS, VERIFYING"]
    QueryFindings --> GroupAssets["Agrupar hallazgos por activo objetivo"]

    subgraph Correlacion ["Evaluadores Heurísticos de Rutas"]
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

## 3. Flujo de Escaneo de Postura Cloud Multicloud (CSPM AWS & Azure)

Inspección automatizada y periódica de cuentas en nubes públicas sin requerir instalación de agentes en máquinas virtuales.

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

## 4. Flujo del Ciclo de Vida del Hallazgo y Gestión de SLAs

Control de estados formal con cálculo de vencimiento y re-testeo directo:

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
        [*] --> ON_TRACK: Dentro del plazo de atención
        ON_TRACK --> APPROACHING: Faltan < 48 horas para vencer SLA
        APPROACHING --> OVERDUE: Fecha límite superada (Incumplimiento)
    }
```

---

## 5. Flujo del Algoritmo Determinista del Security Score

El cálculo de la calificación global opera de forma 100% matemática y reproducible:

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
