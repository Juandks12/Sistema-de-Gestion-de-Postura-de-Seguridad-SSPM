import { CloudProvider } from '@prisma/client';
import { CSPM_RULES_MAP } from '../cloud/cspm.catalog';

export interface RemediationSnippet {
  platform:
    | 'Nginx'
    | 'Apache'
    | 'Cloudflare'
    | 'Docker'
    | 'Spring Boot'
    | 'Node.js'
    | 'AWS CLI'
    | 'Azure CLI'
    | 'Terraform'
    | 'General';
  code: string;
  description: string;
}

export interface RemediationGuide {
  ruleId: string;
  owasp?: string;
  cwe?: string;
  summary: string;
  verificationCommand?: string;
  snippets: RemediationSnippet[];
}

const REMEDIATION_CATALOG: Record<string, Omit<RemediationGuide, 'ruleId'>> = {
  // ------------------------------------------------------------- Cabeceras HTTP
  'HDR-HSTS-MISSING': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
    summary:
      'Habilite la cabecera HTTP Strict Transport Security (HSTS) para obligar a los navegadores a comunicarse exclusivamente mediante HTTPS durante al menos un año.',
    verificationCommand: 'curl -sI https://target.com | grep -i "strict-transport-security"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Agregue la directiva dentro del bloque server {} HTTPS en /etc/nginx/sites-available/:',
        code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
      },
      {
        platform: 'Apache',
        description: 'Agregue en .htaccess o en el VirtualHost (:443) con mod_headers habilitado:',
        code: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
      },
      {
        platform: 'Cloudflare',
        description: 'En el panel de Cloudflare, navegue a SSL/TLS > Edge Certificates > HSTS y actívelo con max-age=12 meses.',
        code: 'Status: Enabled\nMax-Age: 12 months (31536000)\nInclude subdomains: Yes\nPreload: Yes',
      },
    ],
  },
  'HDR-HSTS-SHORT': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
    summary:
      'Incremente el parámetro max-age de HSTS a un mínimo de 15552000 segundos (6 meses) o preferiblemente 31536000 (1 año) con includeSubDomains.',
    verificationCommand: 'curl -sI https://target.com | grep -i "strict-transport-security"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Actualice el valor de max-age en la directiva add_header:',
        code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
      },
      {
        platform: 'Apache',
        description: 'Actualice la cabecera en el VirtualHost:',
        code: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
      },
    ],
  },
  'HDR-CSP-MISSING': {
    owasp: 'A03:2021 – Injection (Cross-Site Scripting)',
    cwe: 'CWE-79: Cross-Site Scripting (XSS)',
    summary:
      'Configure una política de Content-Security-Policy (CSP) robusta para prevenir la ejecución no autorizada de scripts y ataques de inyección.',
    verificationCommand: 'curl -sI https://target.com | grep -i "content-security-policy"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Agregue la cabecera en el bloque de servidor:',
        code: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';\" always;",
      },
      {
        platform: 'Apache',
        description: 'Agregue en .htaccess:',
        code: "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';\"",
      },
      {
        platform: 'Node.js',
        description: 'En aplicaciones Express.js, utilice el middleware Helmet:',
        code: "import helmet from 'helmet';\napp.use(helmet.contentSecurityPolicy());",
      },
    ],
  },
  'HDR-XFO-MISSING': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-1021: Improper Restriction of Rendered UI Layers or Frames (Clickjacking)',
    summary:
      'Configure X-Frame-Options o CSP frame-ancestors para impedir que su sitio sea incrustado en iframes maliciosos (Clickjacking).',
    verificationCommand: 'curl -sI https://target.com | grep -i "x-frame-options"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Agregue en nginx.conf:',
        code: 'add_header X-Frame-Options "SAMEORIGIN" always;',
      },
      {
        platform: 'Apache',
        description: 'Agregue en su VirtualHost:',
        code: 'Header always set X-Frame-Options "SAMEORIGIN"',
      },
    ],
  },
  'HDR-XCTO-MISSING': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-16: Configuration',
    summary:
      'Active X-Content-Type-Options: nosniff para evitar que los navegadores interpreten archivos con tipos MIME incorrectos (MIME sniffing).',
    verificationCommand: 'curl -sI https://target.com | grep -i "x-content-type-options"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Agregue en el bloque server:',
        code: 'add_header X-Content-Type-Options "nosniff" always;',
      },
      {
        platform: 'Apache',
        description: 'Agregue en el bloque VirtualHost:',
        code: 'Header always set X-Content-Type-Options "nosniff"',
      },
    ],
  },
  'HDR-SERVER-VERSION': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-200: Exposure of Sensitive Information',
    summary:
      'Oculte el número de versión específico en la cabecera Server para dificultar el fingerprinting automatizado de vulnerabilidades.',
    verificationCommand: 'curl -sI https://target.com | grep -i "server:"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'En /etc/nginx/nginx.conf dentro de http {}:',
        code: 'server_tokens off;',
      },
      {
        platform: 'Apache',
        description: 'En /etc/apache2/conf-available/security.conf:',
        code: 'ServerTokens Prod\nServerSignature Off',
      },
    ],
  },
  'HDR-POWERED-BY': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-200: Exposure of Sensitive Information',
    summary:
      'Elimine la cabecera X-Powered-By para no revelar el lenguaje de programación ni el framework en uso.',
    verificationCommand: 'curl -sI https://target.com | grep -i "x-powered-by"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Si Nginx actúa como reverse proxy:',
        code: 'proxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;',
      },
      {
        platform: 'General',
        description: 'En PHP (php.ini):',
        code: 'expose_php = Off',
      },
      {
        platform: 'Node.js',
        description: 'En Express.js:',
        code: "app.disable('x-powered-by');",
      },
    ],
  },
  'HDR-HTTP-NO-REDIRECT': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
    summary:
      'Configure una redirección 301 permanente en el puerto 80 (HTTP) hacia https://$host$request_uri.',
    verificationCommand: 'curl -sI http://target.com | grep -E "HTTP/|Location"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Bloque server HTTP en /etc/nginx/sites-available/:',
        code: 'server {\n    listen 80;\n    server_name example.com www.example.com;\n    return 301 https://$host$request_uri;\n}',
      },
      {
        platform: 'Apache',
        description: 'En .htaccess o VirtualHost :80:',
        code: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]',
      },
      {
        platform: 'Cloudflare',
        description: 'Navegue a SSL/TLS > Edge Certificates y active "Always Use HTTPS".',
        code: 'Always Use HTTPS: On',
      },
    ],
  },
  'HDR-CORS-WILDCARD': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains',
    summary:
      'Restrinja la cabecera Access-Control-Allow-Origin a los orígenes específicos autorizados en lugar de permitir el comodín * en respuestas que manejen datos de la aplicación.',
    verificationCommand: 'curl -sI -H "Origin: https://evil.com" https://target.com | grep -i "access-control-allow-origin"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Restrinja el origen mediante un mapeo en nginx.conf:',
        code: 'map $http_origin $cors_origin {\n    default "";\n    "~^https?://(app\\.example\\.com|admin\\.example\\.com)$" $http_origin;\n}\nserver {\n    add_header Access-Control-Allow-Origin $cors_origin always;\n}',
      },
      {
        platform: 'Node.js',
        description: 'En Express usando el middleware cors con whitelist:',
        code: "const cors = require('cors');\nconst whitelist = ['https://app.example.com'];\napp.use(cors({\n  origin: (origin, callback) => {\n    if (!origin || whitelist.includes(origin)) callback(null, true);\n    else callback(new Error('Bloqueado por CORS'));\n  }\n}));",
      },
      {
        platform: 'Spring Boot',
        description: 'En Spring Security o WebMvcConfigurer configure allowedOrigins:',
        code: '@Override\npublic void addCorsMappings(CorsRegistry registry) {\n    registry.addMapping("/**")\n        .allowedOrigins("https://app.example.com")\n        .allowedMethods("GET", "POST", "PUT", "DELETE");\n}',
      },
    ],
  },
  'HDR-CORS-CREDENTIALS-INSECURE': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains',
    summary:
      'No combine Access-Control-Allow-Credentials: true con comodines ni refleje ciegamente el Origin del cliente. Implemente una validación estricta de dominios de confianza antes de responder.',
    verificationCommand: 'curl -sI -H "Origin: https://evil.com" https://target.com | grep -iE "access-control-allow-(origin|credentials)"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Verifique el origen contra una lista blanca antes de añadir las cabeceras:',
        code: 'if ($http_origin ~* "^https?://(app\\.example\\.com)$") {\n    add_header Access-Control-Allow-Origin "$http_origin" always;\n    add_header Access-Control-Allow-Credentials "true" always;\n}',
      },
      {
        platform: 'Node.js',
        description: 'En Express con cors configure origin explícito con credentials:',
        code: "app.use(cors({\n  origin: 'https://app.example.com',\n  credentials: true\n}));",
      },
      {
        platform: 'Spring Boot',
        description: 'Configure allowedOriginPatterns o allowedOrigins estrictos con allowCredentials:',
        code: 'corsConfiguration.setAllowedOrigins(List.of("https://app.example.com"));\ncorsConfiguration.setAllowCredentials(true);',
      },
    ],
  },
  'HDR-COOKIE-INSECURE': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute',
    summary:
      'Configure el atributo Secure en todas las cookies emitidas sobre conexiones HTTPS para evitar que el navegador las envíe en peticiones no cifradas.',
    verificationCommand: 'curl -sI https://target.com | grep -i "set-cookie"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Añada la directiva proxy_cookie_flags en Nginx:',
        code: 'proxy_cookie_flags ~ secure;',
      },
      {
        platform: 'Node.js',
        description: 'En express-session configure cookie.secure:',
        code: "app.use(session({\n  secret: process.env.SESSION_SECRET,\n  cookie: { secure: true, httpOnly: true, sameSite: 'lax' }\n}));",
      },
      {
        platform: 'Spring Boot',
        description: 'En application.properties configure cookies seguras:',
        code: 'server.servlet.session.cookie.secure=true\nserver.servlet.session.cookie.http-only=true',
      },
    ],
  },
  'HDR-COOKIE-NO-HTTPONLY': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-1004: Sensitive Cookie Without HttpOnly Flag',
    summary:
      'Active el atributo HttpOnly en todas las cookies de sesión y autenticación para evitar que sean leídas por scripts en el navegador mediante document.cookie en caso de XSS.',
    verificationCommand: 'curl -sI https://target.com | grep -i "set-cookie"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Fuerce el flag HttpOnly en cookies proxy:',
        code: 'proxy_cookie_flags ~ httponly;',
      },
      {
        platform: 'General',
        description: 'En PHP (php.ini):',
        code: 'session.cookie_httponly = 1\nsession.cookie_secure = 1',
      },
      {
        platform: 'Node.js',
        description: 'En express-session:',
        code: 'cookie: { httpOnly: true, secure: true, sameSite: "lax" }',
      },
    ],
  },
  'HDR-COOKIE-NO-SAMESITE': {
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-1275: Sensitive Cookie with Improper SameSite Attribute',
    summary:
      'Configure explícitamente el atributo SameSite (Lax o Strict) en las cookies de sesión para mitigar ataques de Cross-Site Request Forgery (CSRF).',
    verificationCommand: 'curl -sI https://target.com | grep -i "set-cookie"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Añada el flag samesite en Nginx:',
        code: 'proxy_cookie_flags ~ samesite=lax;',
      },
      {
        platform: 'General',
        description: 'En PHP (php.ini):',
        code: 'session.cookie_samesite = "Lax"',
      },
      {
        platform: 'Spring Boot',
        description: 'En application.properties:',
        code: 'server.servlet.session.cookie.same-site=lax',
      },
    ],
  },
  'HDR-COOKIE-SAMESITE-NONE-INSECURE': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-1275: Sensitive Cookie with Improper SameSite Attribute',
    summary:
      'Las cookies configuradas con SameSite=None deben incluir obligatoriamente el atributo Secure para ser aceptadas por navegadores modernos y protegerse en tránsito.',
    verificationCommand: 'curl -sI https://target.com | grep -i "set-cookie"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Configure proxy_cookie_flags para añadir secure junto a samesite:',
        code: 'proxy_cookie_flags ~ samesite=none secure;',
      },
      {
        platform: 'Node.js',
        description: 'En Express / cookie-parser:',
        code: "res.cookie('token', value, { sameSite: 'none', secure: true, httpOnly: true });",
      },
    ],
  },
  'HDR-CORS-ORIGIN-REFLECTION': {
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains',
    summary:
      'Restrinja Access-Control-Allow-Origin a una lista blanca explícita de dominios confiables y nunca refleje arbitrariamente la cabecera Origin cuando Access-Control-Allow-Credentials sea true.',
    verificationCommand: 'curl -sI -H "Origin: https://malicious.com" https://target.com | grep -i "access-control"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Configure una lista blanca estricta con directiva map en Nginx:',
        code: 'map $http_origin $cors_origin {\n  default "";\n  "~^https://(www\\.)?midominio\\.com$" $http_origin;\n}\n\nadd_header Access-Control-Allow-Origin $cors_origin always;\nadd_header Access-Control-Allow-Credentials "true" always;',
      },
      {
        platform: 'Node.js',
        description: 'En middleware cors de Express declare la lista de dominios autorizados:',
        code: 'import cors from "cors";\nconst whitelist = ["https://comercio.com", "https://app.comercio.com"];\napp.use(cors({\n  origin: (origin, callback) => {\n    if (!origin || whitelist.includes(origin)) callback(null, true);\n    else callback(new Error("Bloqueado por política CORS"));\n  },\n  credentials: true\n}));',
      },
    ],
  },
  'WEB-WAF-ABSENT': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-693: Protection Mechanism Failure',
    summary:
      'Implemente un Web Application Firewall (WAF) perimetral para mitigar ataques DDoS, bots automatizados, scraping y explotación de vulnerabilidades en capa de aplicación.',
    verificationCommand: 'curl -sI https://target.com | grep -Ei "cf-ray|x-amz-cf-id|x-sucuri|x-akamai"',
    snippets: [
      {
        platform: 'Cloudflare',
        description: 'Active el proxy WAF administrado de Cloudflare (nube naranja):',
        code: '1. En DNS active el proxy (nube naranja) para los registros A/CNAME web.\n2. En Security > WAF habilite el Cloudflare Managed Ruleset en modo Block.\n3. Configure Rate Limiting para proteger endpoints de checkout y autenticación.',
      },
      {
        platform: 'AWS CLI',
        description: 'Asocie una Web ACL de AWS WAFv2 a la distribución de CloudFront o Application Load Balancer:',
        code: 'aws wafv2 associate-web-acl --web-acl-arn <ARN_DE_TU_WAF> --resource-arn <ARN_DEL_ALB_O_APIGW>',
      },
    ],
  },
  'WEB-HTTP-METHODS-DANGEROUS': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-650: Trusting HTTP Permission Methods on the Server Side',
    summary:
      'Deshabilite métodos HTTP no seguros (TRACE, TRACK, PUT, DELETE) en peticiones públicas para prevenir ataques Cross-Site Tracing (XST) y manipulación no autorizada.',
    verificationCommand: 'curl -sI -X OPTIONS https://target.com | grep -i "allow"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Restrinja los métodos HTTP permitidos en el bloque server o location:',
        code: 'if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) {\n  return 405;\n}',
      },
      {
        platform: 'Apache',
        description: 'Deniegue métodos no permitidos y deshabilite TRACE en httpd.conf / .htaccess:',
        code: '<LimitExcept GET POST HEAD OPTIONS>\n  Deny from all\n</LimitExcept>\nTraceEnable Off',
      },
    ],
  },
  'WEB-SRI-MISSING-EXTERNAL-SCRIPT': {
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    cwe: 'CWE-353: Missing Support for Integrity Check',
    summary:
      'Incorpore Subresource Integrity (SRI) en todas las etiquetas <script> que consuman recursos externos de CDNs para evitar ataques Magecart / E-Skimming (PCI-DSS v4.0 Req. 6.4.3).',
    verificationCommand: 'curl -s https://target.com | grep -i "<script.*src.*integrity"',
    snippets: [
      {
        platform: 'General',
        description: 'Genere el hash criptográfico sha384 del script e incorpórelo con crossorigin="anonymous":',
        code: '<!-- Obtener hash: cat script.js | openssl dgst -sha384 -binary | openssl base64 -A -->\n<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"\n  crossorigin="anonymous"></script>',
      },
      {
        platform: 'Node.js',
        description: 'Automatice la inyección de SRI en bundles frontend con webpack-subresource-integrity:',
        code: 'import { SubresourceIntegrityPlugin } from "webpack-subresource-integrity";\nexport default {\n  output: { crossOriginLoading: "anonymous" },\n  plugins: [new SubresourceIntegrityPlugin({ hashFuncNames: ["sha384"] })]\n};',
      },
    ],
  },
  'WEB-MIXED-CONTENT': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-311: Missing Encryption of Sensitive Data',
    summary:
      'Asegure que todos los scripts, imágenes, estilos e iframes se carguen exclusivamente mediante https:// o active la directiva CSP upgrade-insecure-requests.',
    verificationCommand: 'curl -sI https://target.com | grep -i "content-security-policy.*upgrade-insecure-requests"',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Fuerce la actualización automática de recursos HTTP a HTTPS mediante Content-Security-Policy:',
        code: "add_header Content-Security-Policy \"upgrade-insecure-requests; default-src https: data: 'unsafe-inline' 'unsafe-eval';\" always;",
      },
      {
        platform: 'Apache',
        description: 'Configure en .htaccess la cabecera CSP de actualización segura:',
        code: 'Header always set Content-Security-Policy "upgrade-insecure-requests"',
      },
      {
        platform: 'Cloudflare',
        description: 'Active la reescritura automática en el panel de Cloudflare:',
        code: 'Navegue a SSL/TLS > Edge Certificates y active "Automatic HTTPS Rewrites".',
      },
    ],
  },
  'WEB-INSECURE-FORM-ACTION': {
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
    summary:
      'Actualice el atributo action de los formularios de autenticación y pago para que envíen sus datos exclusivamente a endpoints HTTPS con cifrado TLS.',
    verificationCommand: 'curl -s https://target.com | grep -i "<form.*action=.*http:"',
    snippets: [
      {
        platform: 'General',
        description: 'Asegúrese de usar URLs absolutas HTTPS o rutas relativas en formularios sensibles:',
        code: '<!-- Seguro: action relativo o con protocolo HTTPS explícito -->\n<form method="POST" action="https://comercio.com/checkout/pay">\n  <input type="password" name="password" />\n  <button type="submit">Pagar</button>\n</form>',
      },
      {
        platform: 'Nginx',
        description: 'Redirija incondicionalmente cualquier petición HTTP a HTTPS con código 301:',
        code: 'server {\n  listen 80 default_server;\n  return 301 https://$host$request_uri;\n}',
      },
    ],
  },
  'WEB-JS-SECRET-LEAK': {
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    summary:
      'Revoque inmediatamente las credenciales expuestas y mueva las llaves privadas de Stripe, MercadoPago, Wompi o AWS exclusivamente al entorno de ejecución backend.',
    verificationCommand: 'git log -S "sk_live_" --oneline',
    snippets: [
      {
        platform: 'Node.js',
        description: 'Mantenga las llaves privadas exclusivamente en variables de entorno del servidor backend:',
        code: '// Backend (Node.js/NestJS/Express):\nimport Stripe from "stripe";\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY); // sk_live_... nunca en frontend',
      },
      {
        platform: 'General',
        description: 'Pasos urgentes de rotación y revocación en pasarelas de pago:',
        code: '# 1. Stripe Dashboard > Developers > API keys > Revoke key\n# 2. MercadoPago Developers > Credenciales de producción > Renovar Secret\n# 3. AWS IAM Console > Security credentials > Deactivate & Delete Access Key',
      },
    ],
  },
  'PATH-SOURCEMAP-EXPOSED': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-540: Inclusion of Sensitive Information in Source Code',
    summary:
      'Deshabilite la generación o subida de archivos Source Map (.js.map) a entornos de producción para evitar la exposición del código fuente original de la aplicación.',
    verificationCommand: 'curl -sI https://target.com/static/js/main.js.map',
    snippets: [
      {
        platform: 'Node.js',
        description: 'Desactive source maps en la configuración de empaquetado de producción (Vite, Next.js, Webpack):',
        code: '// vite.config.ts\nexport default defineConfig({\n  build: { sourcemap: false }\n});',
      },
      {
        platform: 'Nginx',
        description: 'Deniegue el acceso público a archivos .map en Nginx:',
        code: 'location ~* \\.map$ {\n  deny all;\n  return 404;\n}',
      },
      {
        platform: 'Apache',
        description: 'Bloquee el acceso a archivos de mapeo en Apache:',
        code: '<FilesMatch "\\.map$">\n  Require all denied\n</FilesMatch>',
      },
    ],
  },
  'PATH-ROBOTS-SENSITIVE-EXPOSED': {
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-200: Exposure of Sensitive Information',
    summary:
      'Elimine del archivo robots.txt los directorios administrativos o rutas privadas de la tienda y proteja el acceso mediante autenticación o listas de control en el servidor.',
    verificationCommand: 'curl -s https://target.com/robots.txt',
    snippets: [
      {
        platform: 'General',
        description: 'Plantilla de robots.txt seguro sin listar rutas secretas o administrativas:',
        code: 'User-agent: *\nDisallow: /checkout/thank-you\nDisallow: /api/\nSitemap: https://target.com/sitemap.xml',
      },
      {
        platform: 'Nginx',
        description: 'Proteja el panel administrativo en el servidor web mediante IP o autenticación básica:',
        code: 'location ^~ /admin/ {\n  allow 192.168.1.0/24;\n  deny all;\n  auth_basic "Restricted Area";\n  auth_basic_user_file /etc/nginx/.htpasswd;\n}',
      },
    ],
  },
  'CMS-WP-USER-ENUMERATION': {
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-200: Exposure of Sensitive Information',
    summary:
      'Bloquee el endpoint público de enumeración de usuarios /wp-json/wp/v2/users en WordPress/WooCommerce para prevenir ataques de credential stuffing.',
    verificationCommand: 'curl -sI https://target.com/wp-json/wp/v2/users',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Deniegue el acceso al endpoint REST de usuarios de WordPress en Nginx:',
        code: 'location ~ ^/wp-json/wp/v2/users {\n  return 403;\n}',
      },
      {
        platform: 'Apache',
        description: 'Bloquee la ruta en .htaccess con mod_rewrite:',
        code: '<IfModule mod_rewrite.c>\n  RewriteEngine On\n  RewriteRule ^wp-json/wp/v2/users - [F,L]\n</IfModule>',
      },
      {
        platform: 'Cloudflare',
        description: 'Cree una regla de Firewall WAF en Cloudflare:',
        code: '(http.request.uri.path contains "/wp-json/wp/v2/users") -> Action: Block',
      },
    ],
  },
  'CMS-WP-XMLRPC-ENABLED': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-307: Improper Restriction of Excessive Authentication Attempts',
    summary:
      'Deshabilite el acceso público a /xmlrpc.php en WordPress para eliminar vectores de fuerza bruta multicall y amplificación DDoS por pingback.',
    verificationCommand: 'curl -sI https://target.com/xmlrpc.php',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Bloquee incondicionalmente las peticiones hacia xmlrpc.php:',
        code: 'location = /xmlrpc.php {\n  deny all;\n  access_log off;\n  return 403;\n}',
      },
      {
        platform: 'Apache',
        description: 'Deniegue el acceso al archivo en .htaccess:',
        code: '<Files "xmlrpc.php">\n  Require all denied\n</Files>',
      },
      {
        platform: 'Cloudflare',
        description: 'Regla WAF de bloqueo en Cloudflare:',
        code: '(http.request.uri.path eq "/xmlrpc.php") -> Action: Block',
      },
    ],
  },
  'CMS-WP-DEBUG-LOG-EXPOSED': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
    summary:
      'Deshabilite WP_DEBUG_LOG en wp-config.php en producción, elimine el archivo /wp-content/debug.log y bloquee el acceso a archivos de registro.',
    verificationCommand: 'curl -sI https://target.com/wp-content/debug.log',
    snippets: [
      {
        platform: 'General',
        description: 'En wp-config.php asegúrese de que el registro de depuración esté desactivado:',
        code: 'define( "WP_DEBUG", false );\ndefine( "WP_DEBUG_LOG", false );\ndefine( "WP_DEBUG_DISPLAY", false );',
      },
      {
        platform: 'Nginx',
        description: 'Bloquee la descarga de cualquier archivo con extensión .log:',
        code: 'location ~* \\.log$ {\n  deny all;\n  return 404;\n}',
      },
      {
        platform: 'Apache',
        description: 'Deniegue archivos de registro en Apache:',
        code: '<FilesMatch "\\.log$">\n  Require all denied\n</FilesMatch>',
      },
    ],
  },
  'DNS-SUBDOMAIN-TAKEOVER': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-284: Improper Access Control',
    summary:
      'Elimine inmediatamente el registro CNAME huérfano de la zona DNS o vuelva a registrar el recurso en el proveedor cloud (AWS S3, Azure, GitHub, Heroku, Vercel).',
    verificationCommand: 'dig +short CNAME subdominio.target.com',
    snippets: [
      {
        platform: 'General',
        description: 'Procedimiento de resolución de Subdomain Takeover:',
        code: '# 1. Identifique el registro CNAME huérfano:\n#    dig CNAME subdominio.dominio.com\n# 2. Ingrese a su proveedor de DNS (Cloudflare, Route53, GoDaddy) y elimine el registro CNAME huérfano.\n# 3. Si el servicio debe seguir activo, cree de inmediato el recurso en el proveedor cloud antes de que sea reclamado.',
      },
      {
        platform: 'Cloudflare',
        description: 'Elimine el registro CNAME huérfano en Cloudflare DNS:',
        code: 'En Cloudflare Dashboard > DNS > Records: Localice el CNAME y haga clic en "Delete".',
      },
      {
        platform: 'AWS CLI',
        description: 'Si el CNAME apuntaba a un bucket S3 huérfano, reclámelo preventivamente:',
        code: 'aws s3api create-bucket --bucket <nombre-del-bucket-huerfano> --region us-east-1',
      },
    ],
  },
  'PATH-DEV-CONSOLE-EXPOSED': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-200: Exposure of Sensitive Information',
    summary:
      'Deshabilite las consolas interactivas de depuración y profiling en entornos de producción para evitar la ejecución arbitraria de código o exposición de secretos.',
    verificationCommand: 'curl -sI https://target.com/_ignition/health-check',
    snippets: [
      {
        platform: 'General',
        description: 'En Laravel (.env):',
        code: 'APP_DEBUG=false\nAPP_ENV=production',
      },
      {
        platform: 'Nginx',
        description: 'Bloquee el acceso exterior a rutas de profiling y depuración:',
        code: 'location ~* ^/(_profiler|_ignition|telescope|debug) {\n    deny all;\n    return 404;\n}',
      },
    ],
  },
  'PATH-K8S-CONFIG-EXPOSED': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-552: Files or Directories Accessible to External Parties',
    summary:
      'Elimine de inmediato los archivos de credenciales de Kubernetes (.kube/config) del directorio web raíz y revoque los certificados o tokens comprometidos en el clúster.',
    verificationCommand: 'curl -sI https://target.com/.kube/config',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Bloquee el acceso a directorios y archivos ocultos (.kube, .git, .env):',
        code: 'location ~ /\\.(kube|git|env|aws|ssh) {\n    deny all;\n    return 404;\n}',
      },
      {
        platform: 'Apache',
        description: 'Bloquee el acceso a archivos de configuración en .htaccess:',
        code: '<FilesMatch "^\\.(kube|env|git)">\n    Require all denied\n</FilesMatch>',
      },
    ],
  },

  // --------------------------------------------------- Tecnologías y EOL
  'HDR-EOL-TECH': {
    owasp: 'A06:2021 – Vulnerable and Outdated Components',
    cwe: 'CWE-1104: Use of Unmaintained Third Party Components',
    summary:
      'El componente detectado alcanzó su Fin de Soporte (EOL) y no recibe actualizaciones de seguridad. Es crítico planificar la migración a una versión con mantenimiento activo.',
    verificationCommand: 'curl -sI https://target.com | grep -iE "server|powered"',
    snippets: [
      {
        platform: 'General',
        description: 'Si se detectó PHP en EOL (PHP < 8.2), actualice los paquetes del sistema:',
        code: 'sudo apt update && sudo apt install php8.2 php8.2-fpm php8.2-mysql',
      },
      {
        platform: 'Docker',
        description: 'Actualice la imagen base en el Dockerfile hacia la versión LTS activa:',
        code: 'FROM node:20-alpine\n# O para PHP:\nFROM php:8.2-fpm-alpine',
      },
    ],
  },
  'HDR-OUTDATED-TECH': {
    owasp: 'A06:2021 – Vulnerable and Outdated Components',
    cwe: 'CWE-1104: Use of Unmaintained Third Party Components',
    summary:
      'Actualice la versión del servidor o componente a la última versión menor/parche de la rama estable para corregir vulnerabilidades conocidas.',
    verificationCommand: 'curl -sI https://target.com | grep -i "server"',
    snippets: [
      {
        platform: 'General',
        description: 'Actualice paquetes del servidor web:',
        code: 'sudo apt update && sudo apt --only-upgrade install nginx apache2',
      },
    ],
  },

  // --------------------------------------------------- APIs y Microservicios
  'API-SWAGGER-EXPOSED': {
    owasp: 'API7:2023 – Security Misconfiguration',
    cwe: 'CWE-200: Exposure of Sensitive Information',
    summary:
      'La documentación interactiva Swagger UI o la especificación OpenAPI expone el inventario completo de endpoints a usuarios no autenticados. Restrinja su acceso a redes internas o entornos de desarrollo.',
    verificationCommand: 'curl -sI https://target.com/swagger-ui.html',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Bloquee o restrinja el acceso por IP a rutas de Swagger/OpenAPI:',
        code: 'location ~* ^/(swagger-ui|swagger|v[0-9]+/api-docs|openapi\\.json) {\n    allow 10.0.0.0/8;\n    allow 192.168.1.0/24;\n    deny all;\n}',
      },
      {
        platform: 'Spring Boot',
        description: 'Deshabilite Swagger UI en application-prod.properties:',
        code: 'springdoc.swagger-ui.enabled=false\nspringdoc.api-docs.enabled=false',
      },
      {
        platform: 'Docker',
        description: 'En aplicaciones FastAPI / Python, oculte la documentación en producción:',
        code: "import os\nfrom fastapi import FastAPI\nis_prod = os.getenv('ENV') == 'production'\napp = FastAPI(docs_url=None if is_prod else '/docs', redoc_url=None if is_prod else '/redoc')",
      },
    ],
  },
  'API-ACTUATOR-ENV-EXPOSED': {
    owasp: 'API7:2023 – Security Misconfiguration',
    cwe: 'CWE-200: Exposure of Sensitive Information',
    summary:
      'CRÍTICO: Los endpoints /actuator/env o /heapdump exponen variables de entorno, claves secretas y contraseñas en claro. Deben cerrarse inmediatamente en el gateway o en la configuración de la aplicación.',
    verificationCommand: 'curl -sI https://target.com/actuator/env',
    snippets: [
      {
        platform: 'Spring Boot',
        description: 'En application.properties, excluya los endpoints peligrosos o exponga solo health:',
        code: 'management.endpoints.web.exposure.include=health,info\nmanagement.endpoints.web.exposure.exclude=env,heapdump,configprops,logfile',
      },
      {
        platform: 'Nginx',
        description: 'Bloquee cualquier acceso público a /actuator en el reverse proxy:',
        code: 'location ^~ /actuator {\n    deny all;\n    return 404;\n}',
      },
      {
        platform: 'Cloudflare',
        description: 'Cree una regla de Firewall (WAF) que bloquee la URI:',
        code: 'Expression: (http.request.uri.path contains "/actuator")\nAction: Block',
      },
    ],
  },
  'API-GRAPHQL-INTROSPECTION': {
    owasp: 'API7:2023 – Security Misconfiguration',
    cwe: 'CWE-200: Exposure of Sensitive Information',
    summary:
      'La introspección GraphQL permite descargar la totalidad del esquema de la base de datos y la API. Debe desactivarse en producción.',
    verificationCommand: 'curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" -d \'{"query":"{__schema{types{name}}}"}\'',
    snippets: [
      {
        platform: 'Node.js',
        description: 'En Apollo Server, deshabilite la introspección en producción:',
        code: "import { ApolloServer } from '@apollo/server';\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== 'production',\n});",
      },
      {
        platform: 'Nginx',
        description: 'Bloquee peticiones con introspección en el proxy:',
        code: 'location /graphql {\n    if ($request_body ~* "__schema") {\n        return 403;\n    }\n    proxy_pass http://backend_upstream;\n}',
      },
    ],
  },
  'API-METRICS-EXPOSED': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-200: Exposure of Sensitive Information',
    summary:
      'Restrinja el endpoint /metrics o Prometheus para que sea accesible solo por el servidor de monitoreo interno.',
    verificationCommand: 'curl -sI https://target.com/metrics',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Permita únicamente la IP del servidor Prometheus:',
        code: 'location /metrics {\n    allow 10.10.0.5; # IP de Prometheus\n    deny all;\n}',
      },
    ],
  },

  // --------------------------------------------------- Rutas sensibles y secretos
  'PATH-SECRETS-EXPOSED': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-552: Files or Directories Accessible to External Parties',
    summary:
      'Archivos con secretos (.env, claves SSH, credenciales) son accesibles públicamente. Deniegue el acceso inmediatamente y rote todas las credenciales expuestas.',
    verificationCommand: 'curl -sI https://target.com/.env',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Deniegue el acceso a todos los archivos ocultos y dotfiles:',
        code: 'location ~ /\\.(?!well-known) {\n    deny all;\n    return 404;\n}',
      },
      {
        platform: 'Apache',
        description: 'En .htaccess o apache2.conf:',
        code: '<FilesMatch "^\\.(?!well-known)">\n    Require all denied\n</FilesMatch>',
      },
    ],
  },
  'PATH-VCS-EXPOSED': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-538: Insertion of Sensitive Information into Externally-Accessible Directory',
    summary:
      'El repositorio .git o .svn está expuesto, permitiendo descargar el código fuente completo y claves de acceso.',
    verificationCommand: 'curl -sI https://target.com/.git/HEAD',
    snippets: [
      {
        platform: 'Nginx',
        description: 'Bloquee el directorio .git:',
        code: 'location ^~ /.git {\n    deny all;\n    return 404;\n}',
      },
      {
        platform: 'Apache',
        description: 'En .htaccess:',
        code: 'RedirectMatch 404 /\\.git',
      },
    ],
  },
  'PATH-DIRECTORY-LISTING': {
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-548: Exposure of Information Through Directory Listing',
    summary:
      'Deshabilite la indexación automática de directorios para evitar que se listen los archivos contenidos.',
    verificationCommand: 'curl -sI https://target.com/uploads/',
    snippets: [
      {
        platform: 'Nginx',
        description: 'En el bloque server o location:',
        code: 'autoindex off;',
      },
      {
        platform: 'Apache',
        description: 'En .htaccess o configuración del sitio:',
        code: 'Options -Indexes',
      },
    ],
  },

  // --------------------------------------------------- Puertos y Servicios
  'SVC-DATABASE-EXPOSED': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-284: Improper Access Control',
    summary:
      'El puerto del motor de base de datos acepta conexiones desde Internet. Bloquee el puerto en el firewall perimetral.',
    verificationCommand: 'nc -zv -w3 target.com 3306 # O 5432, 27017',
    snippets: [
      {
        platform: 'General',
        description: 'En Linux con UFW, restrinja el puerto únicamente a la red de aplicación:',
        code: 'sudo ufw delete allow 5432\nsudo ufw allow from 10.0.0.0/16 to any port 5432',
      },
      {
        platform: 'Cloudflare',
        description: 'En AWS Security Groups, elimine la regla Inbound 0.0.0.0/0 para el puerto de BD.',
        code: 'Security Group Inbound Rule:\nType: PostgreSQL / MySQL\nSource: sg-app-servers (o subred privada)',
      },
    ],
  },
  'SVC-REMOTE-DESKTOP': {
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-284: Improper Access Control',
    summary:
      'El puerto de escritorio remoto (RDP 3389 / VNC 5900) está abierto al público. Debe ser accesible únicamente mediante VPN corporativa o Bastion Host.',
    verificationCommand: 'nc -zv -w3 target.com 3389',
    snippets: [
      {
        platform: 'General',
        description: 'Cierre el puerto en el firewall del host:',
        code: 'sudo ufw deny 3389\n# En Windows PowerShell:\nDisable-NetFirewallRule -DisplayGroup "Remote Desktop"',
      },
    ],
  },

  // --------------------------------------------------- Certificados TLS
  'TLS-EXPIRED': {
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-298: Improper Validation of Certificate Expiration',
    summary:
      'Renueve el certificado SSL/TLS de inmediato y configure un mecanismo de renovación automática (ACME / Certbot).',
    verificationCommand: 'openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -dates',
    snippets: [
      {
        platform: 'General',
        description: 'Renueve con Certbot (Let\'s Encrypt):',
        code: 'sudo certbot renew --force-renewal\nsudo systemctl reload nginx',
      },
    ],
  },

  // --------------------------------------------------- Correo Electrónico
  'MAIL-DMARC-MISSING': {
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-346: Origin Validation Error',
    summary:
      'Publique un registro DNS TXT DMARC en _dmarc.dominio.com para evitar la suplantación de identidad en correos salientes.',
    verificationCommand: 'dig +short TXT _dmarc.target.com',
    snippets: [
      {
        platform: 'General',
        description: 'Cree el registro DNS TXT en su proveedor de dominio:',
        code: 'Nombre: _dmarc.example.com\nTipo: TXT\nValor: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; pct=100"',
      },
    ],
  },
};

/**
 * Obtiene la guía de remediación enriquecida para una regla específica.
 * Si no cuenta con una guía detallada estática, genera una guía por defecto
 * basada en la recomendación de la regla.
 */
export function getRemediationGuide(ruleId: string, fallbackRecommendation?: string): RemediationGuide {
  const guide = REMEDIATION_CATALOG[ruleId];
  if (guide) {
    return { ruleId, ...guide };
  }

  const cspmRule = CSPM_RULES_MAP.get(ruleId);
  if (cspmRule) {
    const cliPlatform = cspmRule.provider === CloudProvider.AWS ? 'AWS CLI' : 'Azure CLI';
    return {
      ruleId,
      owasp: 'A05:2021 – Security Misconfiguration (Cloud Posture)',
      cwe: cspmRule.complianceControlIds.join(', '),
      summary: cspmRule.recommendation,
      verificationCommand: cspmRule.remediationCli,
      snippets: [
        {
          platform: cliPlatform,
          description: `Comando de remediación directa en ${cliPlatform}:`,
          code: cspmRule.remediationCli,
        },
        {
          platform: 'Terraform',
          description: 'Configuración declarativa segura en Infraestructura como Código (Terraform):',
          code: cspmRule.remediationIac,
        },
      ],
    };
  }

  return {
    ruleId,
    owasp: 'A05:2021 – Security Misconfiguration',
    summary: fallbackRecommendation ?? 'Revise y aplique la configuración recomendada por el fabricante.',
    verificationCommand: undefined,
    snippets: [
      {
        platform: 'General',
        description: 'Recomendación general de mitigación:',
        code: fallbackRecommendation ?? 'Actualice la configuración del componente o aplique las políticas del proveedor.',
      },
    ],
  };
}
