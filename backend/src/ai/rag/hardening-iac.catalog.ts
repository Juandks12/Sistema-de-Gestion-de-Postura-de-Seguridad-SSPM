export interface HardeningGuideItem {
  sourceId: string;
  title: string;
  technology: string;
  content: string;
  remediationIac?: {
    format: 'terraform' | 'nginx' | 'apache' | 'ansible' | 'dockerfile' | 'bash';
    code: string;
    description: string;
  };
  references: string[];
}

export const HARDENING_GUIDES: HardeningGuideItem[] = [
  {
    sourceId: 'GUIDE-HDR-HSTS',
    title: 'Implementación de Strict-Transport-Security (HSTS) y Preloading',
    technology: 'Nginx / Apache / Web Application',
    content: `HTTP Strict Transport Security (HSTS - RFC 6797) previene ataques de degradación de protocolo SSL/TLS (SSL Stripping) y secuestro de sesiones mediante ataques Man-In-The-Middle (MitM).
Debe configurarse con una duración mínima de 31536000 segundos (1 año), incluir subdominios y la directiva 'preload' para su inclusión en las listas canónicas de los navegadores modernos.
Directiva recomendada: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.`,
    remediationIac: {
      format: 'nginx',
      description: 'Bloque de configuración HTTPS en Nginx para cabecera HSTS',
      code: `server {
    listen 443 ssl http2;
    server_name example.com;

    # HSTS con 1 año de expiración, subdominios y preloading
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}`,
    },
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html', 'https://hstspreload.org/'],
  },
  {
    sourceId: 'GUIDE-HDR-CSP',
    title: 'Content-Security-Policy (CSP) Restrictiva anti-XSS y Data Exfiltration',
    technology: 'Nginx / Apache / Frontend SPA',
    content: `Content-Security-Policy (CSP Nivel 3) es la defensa en profundidad primordial contra ataques de Cross-Site Scripting (XSS), Clickjacking e inyecciones de contenido no confiable.
Una política base sólida deniega recursos externos no autorizados, deshabilita 'unsafe-inline' y 'unsafe-eval' mediante nonces o hashes criptográficos, restringe frame-ancestors y fuerza upgrade de solicitudes inseguras.`,
    remediationIac: {
      format: 'nginx',
      description: 'Configuración Nginx de CSP con modo estricto',
      code: `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-rAnd0m'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https: data:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests;" always;`,
    },
    references: ['https://developer.mozilla.org/es/docs/Web/HTTP/CSP', 'https://csp-evaluator.withgoogle.com/'],
  },
  {
    sourceId: 'GUIDE-HDR-CLICKJACKING',
    title: 'Mitigación de Clickjacking con X-Frame-Options y frame-ancestors',
    technology: 'Web Servers',
    content: `Clickjacking o UI Redress Attack engaña al usuario para que haga clic en elementos invisibles embebidos en iframe.
Se debe configurar 'X-Frame-Options: DENY' (o SAMEORIGIN) junto con 'frame-ancestors 'none'' en la cabecera CSP.`,
    remediationIac: {
      format: 'nginx',
      description: 'Directivas contra Clickjacking para Nginx',
      code: `add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;`,
    },
    references: ['https://owasp.org/www-community/attacks/Clickjacking'],
  },
  {
    sourceId: 'GUIDE-TLS-CIPHERS',
    title: 'Bastionado de Protocolos TLS 1.2 / 1.3 y Suites de Cifrado Seguras',
    technology: 'OpenSSL / Nginx / Apache',
    content: `Deshabilitar de forma irreversible protocolos obsoletos e inseguros (SSLv2, SSLv3, TLS 1.0 y TLS 1.1) afectados por ataques POODLE, BEAST y SWEET32.
Habilitar únicamente TLSv1.2 y TLSv1.3 con suites que ofrezcan Perfect Forward Secrecy (ECDHE) y cifrados autenticados (GCM / CHACHA20-POLY1305).`,
    remediationIac: {
      format: 'nginx',
      description: 'Configuración Mozilla Modern/Intermediate TLS para Nginx',
      code: `ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;`,
    },
    references: ['https://ssl-config.mozilla.org/', 'https://csrc.nist.gov/pubs/sp/800/52/r2/final'],
  },
  {
    sourceId: 'GUIDE-PATH-EXPOSURE',
    title: 'Bloqueo de Archivos Sensibles (.git, .env, backups, actuator, swagger)',
    technology: 'Nginx / Reverse Proxy',
    content: `La exposición de repositorios Git (.git/config), archivos de configuración con credenciales (.env, wp-config.php, settings.json), backups (.bak, .sql, .tar.gz) o endpoints de métricas no autenticados (/actuator, /metrics, /debug) permite a atacantes descargar código fuente o secretos de producción.
Se deben bloquear en el proxy inverso antes de alcanzar el servidor de aplicaciones con código 403 o 404.`,
    remediationIac: {
      format: 'nginx',
      description: 'Reglas de denegación de archivos ocultos y sensibles en Nginx',
      code: `# Bloquear acceso a archivos ocultos (iniciados con punto) excepto .well-known
location ~ /\\.(?!well-known) {
    deny all;
    return 404;
}

# Bloquear extensiones sensibles y volcados
location ~* \\.(bak|config|sql|tar|gz|env|log|key|pem|crt)$ {
    deny all;
    return 404;
}

# Proteger endpoints de actuator y spring metrics
location ~ ^/(actuator|env|heapdump|metrics) {
    deny all;
    return 403;
}`,
    },
    references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure'],
  },
  {
    sourceId: 'GUIDE-SSH-HARDENING',
    title: 'Hardening de Demonio SSH (sshd) y Acceso Administrativo',
    technology: 'OpenSSH / Linux',
    content: `El servicio SSH expuesto a Internet sin bastionado es blanco de ataques continuos de fuerza bruta y credential stuffing.
Se debe prohibir el acceso a root (PermitRootLogin no), deshabilitar autenticación por contraseña en favor de llaves ED25519 o RSA 4096 (PasswordAuthentication no), limitar intentos fallidos y aislar el puerto de administración mediante listas blancas de IP o VPN.`,
    remediationIac: {
      format: 'ansible',
      description: 'Tarea Ansible para bastionado de sshd_config',
      code: `- name: Aplicar Hardening SSH
  hosts: all
  become: yes
  tasks:
    - name: Configurar directivas criticas en sshd_config
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        state: present
      loop:
        - { regexp: '^#?PermitRootLogin', line: 'PermitRootLogin no' }
        - { regexp: '^#?PasswordAuthentication', line: 'PasswordAuthentication no' }
        - { regexp: '^#?MaxAuthTries', line: 'MaxAuthTries 3' }
        - { regexp: '^#?ClientAliveInterval', line: 'ClientAliveInterval 300' }
        - { regexp: '^#?ClientAliveCountMax', line: 'ClientAliveCountMax 2' }
      notify: Reiniciar sshd
  handlers:
    - name: Reiniciar sshd
      service:
        name: sshd
        state: restarted`,
    },
    references: ['https://www.cisecurity.org/benchmark/distribution_independent_linux'],
  },
  {
    sourceId: 'GUIDE-AWS-S3-PUBLIC',
    title: 'Bloqueo de Acceso Público y Cifrado por Defecto en AWS S3',
    technology: 'AWS S3 / Terraform',
    content: `Los buckets de AWS S3 con permisos públicos de lectura/escritura son una de las causas más frecuentes de fuga de datos en la nube.
Se debe habilitar la configuración S3 Public Access Block a nivel de cuenta y de bucket, así como forzar el cifrado del lado del servidor (SSE-KMS o SSE-S3) y requerir HTTPS en la política del bucket.`,
    remediationIac: {
      format: 'terraform',
      description: 'Módulo Terraform para bucket S3 seguro y cifrado',
      code: `resource "aws_s3_bucket" "secure_bucket" {
  bucket = "empresa-datos-sensibles-prod"
}

resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "enforce_https" {
  bucket = aws_s3_bucket.secure_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.secure_bucket.arn,
          "\${aws_s3_bucket.secure_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}`,
    },
    references: ['https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html', 'https://www.cisecurity.org/benchmark/amazon_web_services'],
  },
  {
    sourceId: 'GUIDE-AWS-SG-0000',
    title: 'Cierre de Security Groups con Inbound 0.0.0.0/0 en Puertos Administrativos',
    technology: 'AWS VPC / Terraform',
    content: `Reglas de Security Groups que permiten tráfico entrante desde 0.0.0.0/0 (Internet abierto) a puertos de gestión como SSH (22), RDP (3389) o bases de datos (5432, 3306, 27017, 6379) exponen los recursos a ataques de fuerza bruta y explotación directa de vulnerabilidades.
Deben restringirse a CIDRs privados de VPN/Bastion o usar AWS Systems Manager Session Manager para acceso sin puertos abiertos.`,
    remediationIac: {
      format: 'terraform',
      description: 'Terraform para Security Group restringido a CIDR corporativo',
      code: `resource "aws_security_group" "app_servers" {
  name        = "app-sg-production"
  description = "Reglas de trafico para servidores de aplicacion"
  vpc_id      = var.vpc_id

  # Inbound HTTP/HTTPS solo desde balanceador
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # Inbound SSH unicamente desde el CIDR de la VPN corporativa
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"] # Solo red interna privada
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`,
    },
    references: ['https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html'],
  },
  {
    sourceId: 'GUIDE-AZURE-STORAGE-HTTPS',
    title: 'Habilitación de Transferencia Segura (HTTPS) y TLS 1.2 en Azure Storage',
    technology: 'Azure Storage / Terraform',
    content: `Las cuentas de Azure Storage Accounts deben rechazar cualquier conexión no cifrada mediante HTTP y forzar un protocolo TLS mínimo de versión 1.2, mitigando escuchas clandestinas e interceptación de tokens SAS o claves de cuenta.`,
    remediationIac: {
      format: 'terraform',
      description: 'Definición Terraform de Azure Storage Account endurecida',
      code: `resource "azurerm_storage_account" "secure_sa" {
  name                     = "stprodsspmdata"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  enable_https_traffic_only = true
  min_tls_version           = "TLS1_2"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
}`,
    },
    references: ['https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version'],
  },
  {
    sourceId: 'GUIDE-DOCKER-CONTAINER',
    title: 'Empaquetado Seguro de Contenedores Docker (No-Root, Multi-Stage)',
    technology: 'Docker / Kubernetes',
    content: `Ejecutar contenedores como usuario root ('UID 0') permite que un escape de contenedor (container breakout) comprometa el kernel del nodo anfitrión.
Se deben utilizar imágenes base mínimas (distroless o alpine), compilar en etapas multi-stage descartando herramientas de compilación, y declarar explícitamente un usuario sin privilegios.`,
    remediationIac: {
      format: 'dockerfile',
      description: 'Dockerfile multi-stage hardened para Node.js / NestJS',
      code: `# Etapa 1: Build
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --production

# Etapa 2: Runtime seguro
FROM node:22-alpine AS runner
WORKDIR /app

# Crear usuario de sistema sin privilegios
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/package.json ./package.json

# Ejecutar como usuario no privilegiado
USER appuser

EXPOSE 3000
CMD ["node", "dist/main.js"]`,
    },
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'],
  },
];
