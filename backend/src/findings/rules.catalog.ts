import { FindingCategory, FindingSeverity } from '@prisma/client';

/**
 * Catálogo de reglas de hallazgos (RF-08).
 *
 * La severidad sigue los rangos de CVSS v3.1 (sección 6.3.3 del documento):
 *   CRITICAL 9.0-10.0 | HIGH 7.0-8.9 | MEDIUM 4.0-6.9 | LOW 0.1-3.9 | INFO 0.0
 * La puntuación `cvss` es una referencia asignada a cada regla según el vector
 * típico del problema; no sustituye a una evaluación CVE concreta.
 */
export type RemediationEffort = 'QUICK_WIN' | 'MODERATE' | 'STRUCTURAL';

export interface FindingRule {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  cvss: number;
  title: string;
  description: string;
  recommendation: string;
  effort: RemediationEffort;
  estimatedMinutes: number;
  businessImpact: string;
}

const C = FindingCategory;
const S = FindingSeverity;

type RawRule = Omit<FindingRule, 'effort' | 'estimatedMinutes' | 'businessImpact'> &
  Partial<Pick<FindingRule, 'effort' | 'estimatedMinutes' | 'businessImpact'>>;

const rawRules: RawRule[] = [
  // ------------------------------------------------------------------ puertos
  {
    id: 'SVC-CLEARTEXT-REMOTE-ADMIN',
    category: C.EXPOSED_SERVICE,
    severity: S.HIGH,
    cvss: 8.1,
    title: 'Servicio de administración remota sin cifrado expuesto',
    description:
      'Se detectó un servicio de administración remota que transmite credenciales y sesiones en texto claro (Telnet, rlogin o rsh). Cualquier intermediario puede capturar las credenciales.',
    recommendation:
      'Deshabilite el servicio y utilice SSH. Si es imprescindible, restrinja el acceso por firewall o VPN.',
  },
  {
    id: 'SVC-CLEARTEXT-FILE-TRANSFER',
    category: C.EXPOSED_SERVICE,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Servicio de transferencia de archivos sin cifrado expuesto',
    description:
      'FTP o TFTP transmiten credenciales y archivos sin cifrar y suelen permitir enumeración o acceso anónimo.',
    recommendation: 'Sustituya el servicio por SFTP o FTPS y deshabilite el acceso anónimo.',
  },
  {
    id: 'SVC-REMOTE-DESKTOP',
    category: C.EXPOSED_SERVICE,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Escritorio remoto expuesto a Internet',
    description:
      'RDP o VNC accesibles públicamente son objetivo habitual de fuerza bruta y de vulnerabilidades críticas (p. ej. BlueKeep).',
    recommendation:
      'Exponga el escritorio remoto solo a través de VPN o pasarela con autenticación multifactor y restrinja por IP.',
  },
  {
    id: 'SVC-FILE-SHARING',
    category: C.EXPOSED_SERVICE,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Servicio de compartición de archivos expuesto a Internet',
    description:
      'SMB, NetBIOS o NFS expuestos permiten enumeración de recursos y han sido vector de ransomware (p. ej. WannaCry).',
    recommendation: 'Bloquee estos puertos en el perímetro; deben usarse solo en la red interna o mediante VPN.',
  },
  {
    id: 'SVC-DATABASE-EXPOSED',
    category: C.EXPOSED_SERVICE,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Base de datos accesible desde Internet',
    description:
      'El motor de base de datos acepta conexiones desde Internet. Un fallo de configuración o credenciales débiles expondrían toda la información.',
    recommendation:
      'Restrinja el puerto a las IP de la aplicación mediante firewall o grupos de seguridad y exija autenticación fuerte y TLS.',
  },
  {
    id: 'SVC-ORCHESTRATION-EXPOSED',
    category: C.EXPOSED_SERVICE,
    severity: S.CRITICAL,
    cvss: 9.8,
    title: 'API de contenedores u orquestación expuesta',
    description:
      'Docker, Kubernetes o etcd accesibles públicamente suelen permitir ejecución remota de código o acceso a secretos del clúster.',
    recommendation: 'Cierre el puerto al exterior de inmediato y habilite autenticación mutua TLS.',
  },
  {
    id: 'SVC-DIRECTORY-SERVICE',
    category: C.EXPOSED_SERVICE,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Servicio de directorio expuesto',
    description: 'LDAP sin TLS permite enumerar usuarios y capturar credenciales en tránsito.',
    recommendation: 'Exponga únicamente LDAPS y restrinja el acceso a redes de confianza.',
  },
  {
    id: 'SVC-RPC-EXPOSED',
    category: C.EXPOSED_SERVICE,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Servicio RPC expuesto',
    description: 'Los servicios RPC (portmapper, MS-RPC) facilitan enumeración y han sido vector de numerosas vulnerabilidades.',
    recommendation: 'Bloquee el puerto en el perímetro.',
  },
  {
    id: 'SVC-MAIL-CLEARTEXT',
    category: C.EXPOSED_SERVICE,
    severity: S.LOW,
    cvss: 3.7,
    title: 'Servicio de correo sin cifrado expuesto',
    description: 'POP3 o IMAP sin TLS transmiten credenciales en texto claro.',
    recommendation: 'Ofrezca solo las variantes cifradas (POP3S 995, IMAPS 993) o exija STARTTLS.',
  },
  {
    id: 'SVC-OPEN-PORT',
    category: C.EXPOSED_SERVICE,
    severity: S.INFO,
    cvss: 0,
    title: 'Puerto abierto',
    description: 'El puerto acepta conexiones desde Internet. Forma parte de la superficie de ataque y debe estar justificado.',
    recommendation: 'Confirme que el servicio es necesario, mantenga el software actualizado y limite el acceso si es posible.',
  },

  // -------------------------------------------------------------- cabeceras
  {
    id: 'HDR-HSTS-MISSING',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 4.8,
    title: 'Falta la cabecera Strict-Transport-Security',
    description:
      'Sin HSTS el navegador puede ser forzado a usar HTTP en visitas posteriores, lo que permite ataques de degradación (SSL stripping).',
    recommendation: 'Añada `Strict-Transport-Security: max-age=31536000; includeSubDomains` en todas las respuestas HTTPS.',
  },
  {
    id: 'HDR-HSTS-SHORT',
    category: C.HTTP_HEADERS,
    severity: S.LOW,
    cvss: 3.1,
    title: 'Strict-Transport-Security con max-age demasiado corto',
    description: 'Un max-age inferior a 180 días reduce la protección de HSTS entre visitas.',
    recommendation: 'Establezca `max-age=31536000` (un año) o superior.',
  },
  {
    id: 'HDR-CSP-MISSING',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 5.4,
    title: 'Falta la cabecera Content-Security-Policy',
    description: 'Sin CSP el navegador ejecuta cualquier script inyectado, lo que agrava el impacto de XSS.',
    recommendation: 'Defina una política CSP restrictiva, empezando por `default-src \'self\'` y ajustando según los recursos legítimos.',
  },
  {
    id: 'HDR-CSP-UNSAFE',
    category: C.HTTP_HEADERS,
    severity: S.LOW,
    cvss: 3.7,
    title: 'Content-Security-Policy permisiva',
    description: 'La política usa `unsafe-inline`, `unsafe-eval` o comodines `*`, lo que anula gran parte de su protección contra XSS.',
    recommendation: 'Elimine las directivas inseguras y use nonces o hashes para los scripts en línea.',
  },
  {
    id: 'HDR-XFO-MISSING',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 4.3,
    title: 'Sin protección contra clickjacking',
    description: 'No hay `X-Frame-Options` ni directiva `frame-ancestors` en CSP, por lo que la página puede embeberse en un iframe malicioso.',
    recommendation: 'Añada `X-Frame-Options: DENY` o `Content-Security-Policy: frame-ancestors \'none\'`.',
  },
  {
    id: 'HDR-XCTO-MISSING',
    category: C.HTTP_HEADERS,
    severity: S.LOW,
    cvss: 3.1,
    title: 'Falta la cabecera X-Content-Type-Options',
    description: 'Sin `nosniff` el navegador puede interpretar contenido como un tipo distinto al declarado, facilitando ciertos ataques XSS.',
    recommendation: 'Añada `X-Content-Type-Options: nosniff`.',
  },
  {
    id: 'HDR-REFERRER-MISSING',
    category: C.HTTP_HEADERS,
    severity: S.LOW,
    cvss: 2.6,
    title: 'Falta la cabecera Referrer-Policy',
    description: 'Sin política de referrer las URL completas (que pueden contener identificadores o tokens) se envían a sitios de terceros.',
    recommendation: 'Añada `Referrer-Policy: strict-origin-when-cross-origin` o más restrictiva.',
  },
  {
    id: 'HDR-PERMISSIONS-MISSING',
    category: C.HTTP_HEADERS,
    severity: S.INFO,
    cvss: 0,
    title: 'Falta la cabecera Permissions-Policy',
    description: 'La cabecera limita el acceso a funciones del navegador (cámara, geolocalización, micrófono) desde la página y sus iframes.',
    recommendation: 'Añada `Permissions-Policy` deshabilitando las funciones que la aplicación no necesita.',
  },
  {
    id: 'HDR-SERVER-VERSION',
    category: C.HTTP_HEADERS,
    severity: S.LOW,
    cvss: 2.7,
    title: 'La cabecera Server revela la versión del software',
    description: 'Conocer la versión exacta del servidor facilita a un atacante buscar vulnerabilidades específicas.',
    recommendation: 'Configure el servidor para omitir la versión (p. ej. `ServerTokens Prod` en Apache o `server_tokens off` en Nginx).',
  },
  {
    id: 'HDR-POWERED-BY',
    category: C.HTTP_HEADERS,
    severity: S.LOW,
    cvss: 2.7,
    title: 'La cabecera X-Powered-By revela la tecnología',
    description: 'La cabecera expone el lenguaje o framework (y a veces la versión) usado por la aplicación.',
    recommendation: 'Elimine la cabecera `X-Powered-By` en la configuración del servidor o del framework.',
  },
  {
    id: 'HDR-COOKIE-INSECURE',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 4.8,
    title: 'Cookie sin el atributo Secure',
    description: 'Una cookie sin `Secure` puede enviarse por HTTP y ser capturada en la red.',
    recommendation: 'Añada el atributo `Secure` a todas las cookies emitidas por HTTPS.',
  },
  {
    id: 'HDR-COOKIE-NO-HTTPONLY',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 4.3,
    title: 'Cookie de sesión sin el atributo HttpOnly',
    description: 'Sin `HttpOnly` un script inyectado (XSS) puede leer la cookie y robar la sesión.',
    recommendation: 'Añada `HttpOnly` a las cookies de sesión y de autenticación.',
  },
  {
    id: 'HDR-HTTP-NO-REDIRECT',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 5.9,
    title: 'El sitio se sirve por HTTP sin redirigir a HTTPS',
    description: 'El contenido está disponible sin cifrar aunque exista HTTPS; los usuarios pueden navegar y autenticarse por HTTP.',
    recommendation: 'Redirija de forma permanente (301) todo el tráfico HTTP a HTTPS.',
  },
  {
    id: 'HDR-OUTDATED-TECH',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Componente o tecnología web con versión desactualizada detectado',
    description:
      'La cabecera del servidor o respuesta HTTP revela un componente o tecnología con una versión desactualizada o sin soporte activo.',
    recommendation:
      'Actualice el servidor o framework a la versión estable más reciente y configure el servidor para ocultar firmas de versión.',
  },
  {
    id: 'HDR-EOL-TECH',
    category: C.HTTP_HEADERS,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Tecnología web en Fin de Ciclo de Vida (End-of-Life / EOL)',
    description:
      'El servidor web, entorno de ejecución o CMS detectado ha alcanzado su fecha de fin de ciclo de vida (EOL). El fabricante ya no publica parches de seguridad para esta versión, dejándola expuesta a vulnerabilidades conocidas y exploits públicos.',
    recommendation:
      'Planifique y ejecute de forma prioritaria la migración hacia una versión con soporte de seguridad activo.',
  },
  {
    id: 'HDR-CORS-WILDCARD',
    category: C.HTTP_HEADERS,
    severity: S.LOW,
    cvss: 3.7,
    title: 'CORS con comodín permisivo (Access-Control-Allow-Origin: *)',
    description:
      'El servidor devuelve la cabecera Access-Control-Allow-Origin: *, permitiendo que cualquier dominio web de terceros lea las respuestas HTTP mediante peticiones asíncronas fetch/XHR.',
    recommendation:
      'Restrinja Access-Control-Allow-Origin a los dominios de confianza explícitos que requieran consumir el recurso, evitando el uso de comodines en endpoints con datos sensibles.',
  },
  {
    id: 'HDR-CORS-CREDENTIALS-INSECURE',
    category: C.HTTP_HEADERS,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Configuración insegura de CORS con credenciales permitidas',
    description:
      'Se detectó Access-Control-Allow-Credentials: true combinado con Access-Control-Allow-Origin: * o reflejo arbitrario de la cabecera Origin. Esto permite a sitios web maliciosos de terceros extraer datos autenticados o ejecutar acciones en nombre de usuarios legítimos.',
    recommendation:
      'Deshabilite Access-Control-Allow-Credentials o configure una lista blanca estricta (whitelist) de orígenes en el backend sin reflejar dinámicamente cualquier origen proporcionado por el cliente.',
  },
  {
    id: 'HDR-COOKIE-NO-SAMESITE',
    category: C.HTTP_HEADERS,
    severity: S.LOW,
    cvss: 3.7,
    title: 'Cookie sin atributo de protección SameSite',
    description:
      'La cookie se emite sin el atributo SameSite (Lax, Strict o None). Sin este atributo, las peticiones cross-site pueden transmitir la cookie automáticamente, aumentando el riesgo de ataques Cross-Site Request Forgery (CSRF).',
    recommendation:
      'Configure el atributo SameSite=Lax (recomendado para la mayoría de cookies) o SameSite=Strict para cookies críticas de autenticación.',
  },
  {
    id: 'HDR-COOKIE-SAMESITE-NONE-INSECURE',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Cookie con SameSite=None sin atributo Secure',
    description:
      'La cookie especifica SameSite=None pero carece del atributo Secure. La especificación moderna de navegadores exige que SameSite=None se acompañe obligatoriamente de Secure para evitar transmisión en texto claro.',
    recommendation:
      'Añada el atributo Secure a cualquier cookie configurada con SameSite=None.',
  },

  // ------------------------- inspección profunda web, e-commerce y secretos
  {
    id: 'HDR-CORS-ORIGIN-REFLECTION',
    category: C.HTTP_HEADERS,
    severity: S.HIGH,
    cvss: 8.1,
    title: 'CORS con reflexión arbitraria de origen y credenciales permitidas',
    description:
      'El servidor refleja cualquier valor de la cabecera Origin en Access-Control-Allow-Origin y habilita Access-Control-Allow-Credentials: true. Un sitio web malicioso de terceros puede ejecutar peticiones autenticadas y extraer información confidencial de clientes autenticados en el comercio.',
    recommendation:
      'Configure una lista blanca estricta de dominios de confianza permitidos para CORS y nunca refleje arbitrariamente la cabecera Origin cuando Allow-Credentials esté habilitado.',
  },
  {
    id: 'WEB-WAF-ABSENT',
    category: C.HTTP_HEADERS,
    severity: S.LOW,
    cvss: 3.7,
    title: 'Ausencia de Web Application Firewall (WAF) o CDN protectora',
    description:
      'No se detectaron firmas ni cabeceras de protección de un WAF o red de entrega de contenido (Cloudflare, AWS WAF, Akamai, Imperva, Fastly). El comercio o aplicación web se encuentra directamente expuesto a ataques de capa 7, scraping y DDoS.',
    recommendation:
      'Despliegue un Web Application Firewall perimetral para inspeccionar tráfico malicioso, bloquear bots dañinos y proteger formularios críticos contra abusos automatizados.',
  },
  {
    id: 'WEB-HTTP-METHODS-DANGEROUS',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Métodos HTTP peligrosos habilitados públicamente (TRACE, TRACK, PUT, DELETE)',
    description:
      'El servidor responde o declara soporte para métodos HTTP potencialmente peligrosos. El método TRACE/TRACK facilita ataques Cross-Site Tracing (XST) para robar cookies HttpOnly, mientras que PUT o DELETE sin autenticación pueden permitir manipulación no autorizada de recursos.',
    recommendation:
      'Deshabilite los métodos TRACE, TRACK, PUT y DELETE en la configuración global del servidor web o proxy inverso para peticiones públicas no autenticadas.',
  },
  {
    id: 'WEB-SRI-MISSING-EXTERNAL-SCRIPT',
    category: C.HTTP_HEADERS,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Script externo de terceros cargado sin Subresource Integrity (SRI) / Riesgo Magecart',
    description:
      'Se cargan bibliotecas o scripts JavaScript desde orígenes externos (CDNs o terceros) sin el atributo integrity (SRI). Si el proveedor externo es comprometido, un atacante puede inyectar código malicioso (Magecart / E-Skimming) para interceptar números de tarjetas de crédito o contraseñas (PCI-DSS v4.0 Req. 6.4.3 y 11.6.1).',
    recommendation:
      'Agregue el atributo integrity con un hash criptográfico (sha256, sha384 o sha512) y crossorigin="anonymous" a todos los elementos <script> externos, o albergue los scripts localmente.',
  },
  {
    id: 'WEB-MIXED-CONTENT',
    category: C.HTTP_HEADERS,
    severity: S.HIGH,
    cvss: 7.4,
    title: 'Contenido mixto activo (HTTP dentro de HTTPS) detectado',
    description:
      'La aplicación se sirve por HTTPS pero carga scripts o iframes a través de HTTP sin cifrado. Un atacante intermediario (Man-In-The-Middle) puede modificar estos recursos no cifrados y tomar control de la sesión del usuario o de la tienda.',
    recommendation:
      'Actualice todas las referencias de recursos externos e internos para utilizar https:// o URLs relativas a protocolo, y configure la cabecera Content-Security-Policy: upgrade-insecure-requests.',
  },
  {
    id: 'WEB-INSECURE-FORM-ACTION',
    category: C.HTTP_HEADERS,
    severity: S.CRITICAL,
    cvss: 9.1,
    title: 'Formulario sensible envía credenciales o datos de pago vía HTTP sin cifrar',
    description:
      'Un formulario con campos de contraseña o información de pago apunta su atributo action a un endpoint HTTP sin cifrado TLS. La información confidencial del usuario viajará en texto plano a través de la red.',
    recommendation:
      'Asegúrese de que el atributo action del formulario apunte estrictamente a un endpoint HTTPS válido o a una ruta relativa en un host HTTPS.',
  },
  {
    id: 'WEB-JS-SECRET-LEAK',
    category: C.HTTP_HEADERS,
    severity: S.CRITICAL,
    cvss: 9.3,
    title: 'Fuga de secretos o llaves privadas de pago en bundles JavaScript de frontend',
    description:
      'Se identificaron llaves privadas o tokens de producción (Stripe Secret Key, MercadoPago Access Token, Wompi Private Key, credenciales AWS IAM o claves privadas criptográficas) dentro de archivos JavaScript descargables por cualquier visitante.',
    recommendation:
      'Revoque y rote de inmediato todas las credenciales detectadas. Mueva la lógica de pago que requiera secretos privados exclusivamente al backend y asegúrese de no incluir variables de entorno sensibles en los empaquetadores de frontend.',
  },
  {
    id: 'PATH-SOURCEMAP-EXPOSED',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Archivo Source Map (.js.map) expuesto en producción',
    description:
      'Se detectaron archivos de mapeo de código fuente (.js.map) accesibles públicamente en producción. Esto permite a cualquier usuario o atacante reconstruir el código fuente original TypeScript/React/Vue, comentarios internos, nombres de variables y lógica de negocio privada.',
    recommendation:
      'Deshabilite la generación de source maps en el build de producción o configure el servidor web/CDN para denegar el acceso a archivos con extensión .map.',
  },
  {
    id: 'PATH-ROBOTS-SENSITIVE-EXPOSED',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Archivo robots.txt expone rutas sensibles o administrativas',
    description:
      'El archivo /robots.txt contiene directivas Disallow que revelan directorios de administración, pasarelas de pago, paneles de gestión o endpoints privados accesibles desde Internet.',
    recommendation:
      'Elimine del archivo robots.txt las rutas que no deban ser descubiertas y aplique controles de autenticación y autorización en el servidor web o WAF.',
  },
  {
    id: 'CMS-WP-USER-ENUMERATION',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Enumeración de usuarios administradores expuesta en WordPress / WooCommerce',
    description:
      'El endpoint REST /wp-json/wp/v2/users devuelve los nombres de usuario y slugs de los administradores y editores de la tienda. Esta información facilita ataques directos de fuerza bruta y credential stuffing.',
    recommendation:
      'Restrinja el acceso público a /wp-json/wp/v2/users mediante plugins de seguridad o directivas del servidor web para requerir autenticación.',
  },
  {
    id: 'CMS-WP-XMLRPC-ENABLED',
    category: C.HTTP_HEADERS,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Interfaz XML-RPC activa en WordPress / WooCommerce (/xmlrpc.php)',
    description:
      'El archivo /xmlrpc.php está activo y accesible. Este protocolo legado permite el método system.multicall para probar miles de combinaciones de contraseñas en una sola petición HTTP y puede ser usado en ataques de amplificación DDoS (pingback).',
    recommendation:
      'Deshabilite XML-RPC bloqueando el acceso al archivo xmlrpc.php en Nginx, Apache o Cloudflare si no utiliza la app móvil oficial de WordPress o integraciones externas legadas.',
  },
  {
    id: 'CMS-WP-DEBUG-LOG-EXPOSED',
    category: C.HTTP_HEADERS,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Archivo debug.log de WordPress expuesto públicamente',
    description:
      'El archivo /wp-content/debug.log es accesible vía HTTP y contiene trazas de error de PHP, consultas SQL, nombres de tablas, rutas completas del sistema de archivos y potencialmente credenciales de conexión.',
    recommendation:
      'Elimine el archivo debug.log, deshabilite WP_DEBUG_LOG en wp-config.php en producción y configure el servidor para prohibir el acceso a archivos .log.',
  },

  // ------------------------------------------------------------------- TLS
  {
    id: 'TLS-EXPIRED',
    category: C.TLS_CERTIFICATE,
    severity: S.CRITICAL,
    cvss: 9.1,
    title: 'Certificado TLS caducado',
    description: 'El certificado ha expirado: los navegadores muestran una advertencia y los usuarios pueden acostumbrarse a ignorarla, facilitando suplantaciones.',
    recommendation: 'Renueve el certificado de inmediato y automatice la renovación (p. ej. ACME / Let\'s Encrypt).',
  },
  {
    id: 'TLS-EXPIRING-7D',
    category: C.TLS_CERTIFICATE,
    severity: S.HIGH,
    cvss: 7.4,
    title: 'Certificado TLS caduca en menos de 7 días',
    description: 'El certificado está a punto de expirar; si no se renueva el sitio dejará de ser confiable.',
    recommendation: 'Renueve el certificado antes de la fecha de expiración.',
  },
  {
    id: 'TLS-EXPIRING-30D',
    category: C.TLS_CERTIFICATE,
    severity: S.MEDIUM,
    cvss: 5.0,
    title: 'Certificado TLS caduca en menos de 30 días',
    description: 'El certificado expira pronto. Conviene planificar la renovación.',
    recommendation: 'Renueve el certificado o verifique que la renovación automática funciona.',
  },
  {
    id: 'TLS-NOT-YET-VALID',
    category: C.TLS_CERTIFICATE,
    severity: S.HIGH,
    cvss: 7.4,
    title: 'Certificado TLS todavía no válido',
    description: 'La fecha de inicio de validez del certificado es futura; los clientes lo rechazarán.',
    recommendation: 'Revise la hora del servidor y el proceso de emisión del certificado.',
  },
  {
    id: 'TLS-HOSTNAME-MISMATCH',
    category: C.TLS_CERTIFICATE,
    severity: S.HIGH,
    cvss: 7.4,
    title: 'El certificado no coincide con el nombre del host',
    description: 'El nombre del activo no aparece en el CN ni en los SAN del certificado; los navegadores mostrarán una advertencia.',
    recommendation: 'Emita un certificado que incluya el nombre del host en el campo Subject Alternative Name.',
  },
  {
    id: 'TLS-UNTRUSTED-CHAIN',
    category: C.TLS_CERTIFICATE,
    severity: S.HIGH,
    cvss: 7.4,
    title: 'Certificado autofirmado o cadena no confiable',
    description: 'La cadena de certificación no llega a una autoridad reconocida, por lo que los clientes no pueden verificar la identidad del servidor.',
    recommendation: 'Use un certificado emitido por una CA reconocida y publique la cadena intermedia completa.',
  },
  {
    id: 'TLS-LEGACY-PROTOCOL',
    category: C.TLS_CERTIFICATE,
    severity: S.MEDIUM,
    cvss: 5.9,
    title: 'El servidor acepta TLS 1.0 o 1.1',
    description: 'Las versiones antiguas de TLS tienen debilidades conocidas (BEAST, POODLE) y están desaconsejadas desde 2020.',
    recommendation: 'Deshabilite TLS 1.0 y 1.1 y acepte únicamente TLS 1.2 y 1.3.',
  },
  {
    id: 'TLS-WEAK-KEY',
    category: C.TLS_CERTIFICATE,
    severity: S.HIGH,
    cvss: 7.4,
    title: 'Clave del certificado demasiado corta',
    description: 'Claves RSA menores de 2048 bits o curvas inferiores a 256 bits se consideran inseguras.',
    recommendation: 'Emita un nuevo certificado con RSA de al menos 2048 bits o ECDSA P-256.',
  },
  {
    id: 'TLS-WEAK-SIGNATURE',
    category: C.TLS_CERTIFICATE,
    severity: S.MEDIUM,
    cvss: 5.9,
    title: 'Certificado firmado con un algoritmo débil',
    description: 'La firma usa SHA-1 o MD5, algoritmos con colisiones prácticas conocidas.',
    recommendation: 'Emita un certificado firmado con SHA-256 o superior.',
  },
  {
    id: 'TLS-NOT-AVAILABLE',
    category: C.TLS_CERTIFICATE,
    severity: S.MEDIUM,
    cvss: 5.9,
    title: 'El servicio web no ofrece HTTPS',
    description: 'El puerto 80 responde pero no hay TLS en el 443: todo el tráfico viaja sin cifrar.',
    recommendation: 'Configure un certificado TLS (p. ej. con Let\'s Encrypt) y redirija HTTP a HTTPS.',
  },

  // ---------------------------------------------------------- rutas sensibles
  {
    id: 'PATH-SECRETS-EXPOSED',
    category: C.SENSITIVE_PATH,
    severity: S.CRITICAL,
    cvss: 9.8,
    title: 'Archivo con credenciales accesible públicamente',
    description: 'Un archivo de configuración con secretos (variables de entorno, claves privadas, credenciales) es descargable desde Internet.',
    recommendation: 'Retire el archivo del directorio público de inmediato, rote todas las credenciales expuestas y bloquee el acceso a archivos ocultos.',
  },
  {
    id: 'PATH-VCS-EXPOSED',
    category: C.SENSITIVE_PATH,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Repositorio de control de versiones expuesto',
    description: 'El directorio .git o .svn es accesible y permite descargar el código fuente completo, incluido su historial.',
    recommendation: 'Deniegue el acceso a los directorios .git y .svn en el servidor web y no despliegue el repositorio en el directorio público.',
  },
  {
    id: 'PATH-BACKUP-EXPOSED',
    category: C.SENSITIVE_PATH,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Copia de seguridad accesible públicamente',
    description: 'Un volcado de base de datos o archivo comprimido de respaldo es descargable desde Internet.',
    recommendation: 'Elimine las copias de seguridad del directorio público y almacénelas en una ubicación privada y cifrada.',
  },
  {
    id: 'PATH-CONFIG-EXPOSED',
    category: C.SENSITIVE_PATH,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Archivo de configuración accesible públicamente',
    description: 'Un archivo de configuración del servidor o de la aplicación es legible y puede revelar rutas, módulos o credenciales.',
    recommendation: 'Bloquee el acceso a los archivos de configuración desde el servidor web.',
  },
  {
    id: 'PATH-DEBUG-INFO',
    category: C.SENSITIVE_PATH,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Página de diagnóstico o depuración expuesta',
    description: 'Páginas como phpinfo, server-status o los endpoints de Actuator revelan versiones, rutas internas, variables de entorno y configuración.',
    recommendation: 'Deshabilite la página en producción o restrinja su acceso a direcciones internas con autenticación.',
  },
  {
    id: 'PATH-DIRECTORY-LISTING',
    category: C.SENSITIVE_PATH,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Listado de directorios habilitado',
    description: 'El servidor muestra el contenido de un directorio, lo que expone la estructura y archivos que no debían ser públicos.',
    recommendation: 'Deshabilite el listado de directorios (`Options -Indexes` en Apache, `autoindex off` en Nginx).',
  },
  {
    id: 'PATH-ADMIN-PANEL',
    category: C.SENSITIVE_PATH,
    severity: S.LOW,
    cvss: 3.7,
    title: 'Panel de administración accesible desde Internet',
    description: 'La interfaz de administración es alcanzable públicamente y puede ser objetivo de fuerza bruta o de vulnerabilidades del panel.',
    recommendation: 'Restrinja el panel por IP o VPN y active autenticación multifactor.',
  },
  {
    id: 'PATH-API-DOCS',
    category: C.SENSITIVE_PATH,
    severity: S.INFO,
    cvss: 0,
    title: 'Documentación de la API accesible públicamente',
    description: 'La especificación OpenAPI/Swagger está publicada y describe todos los endpoints disponibles.',
    recommendation: 'Valore si la documentación debe ser pública; de lo contrario, protéjala con autenticación.',
  },
  {
    id: 'API-SWAGGER-EXPOSED',
    category: C.SENSITIVE_PATH,
    severity: S.LOW,
    cvss: 3.7,
    title: 'Documentación interactiva Swagger / OpenAPI expuesta públicamente',
    description:
      'La interfaz Swagger UI o especificación OpenAPI expone la definición completa de endpoints, parámetros, métodos HTTP y modelos de datos de la API sin autenticación.',
    recommendation:
      'Deshabilite la interfaz Swagger en entornos de producción o limite su acceso mediante autenticación o lista blanca de IPs.',
  },
  {
    id: 'API-ACTUATOR-ENV-EXPOSED',
    category: C.SENSITIVE_PATH,
    severity: S.CRITICAL,
    cvss: 9.8,
    title: 'Endpoints de telemetría y entorno de microservicios expuestos (Actuator /env o /heapdump)',
    description:
      'Se detectó acceso público a endpoints administrativos o de telemetría de Spring Boot (/env, /heapdump, /logfile). Estos endpoints exponen variables de entorno, tokens de nube, cadenas de conexión y memoria RAM del servidor en texto claro.',
    recommendation:
      'Bloquee inmediatamente el acceso exterior al prefijo /actuator y excluya endpoints críticos en la configuración (management.endpoints.web.exposure.exclude=env,heapdump).',
  },
  {
    id: 'API-GRAPHQL-INTROSPECTION',
    category: C.SENSITIVE_PATH,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Introspección GraphQL habilitada en producción',
    description:
      'El endpoint GraphQL responde a consultas de introspección del esquema (__schema), permitiendo a cualquier usuario descargar el catálogo completo de tipos, consultas y mutaciones de la API.',
    recommendation:
      'Deshabilite la introspección GraphQL en entornos productivos (p. ej. introspection: false en Apollo Server o graphql-js).',
  },
  {
    id: 'API-METRICS-EXPOSED',
    category: C.SENSITIVE_PATH,
    severity: S.LOW,
    cvss: 3.1,
    title: 'Métricas operativas de infraestructura expuestas (/metrics o Prometheus)',
    description:
      'El endpoint /metrics o /actuator/prometheus es accesible públicamente sin autenticación, revelando telemetría interna, tasas de error y detalles de la infraestructura.',
    recommendation:
      'Restrinja el acceso al endpoint de métricas únicamente a la red interna o servicio de monitorización mediante mTLS o autenticación básica.',
  },
  {
    id: 'PATH-DEV-CONSOLE-EXPOSED',
    category: C.SENSITIVE_PATH,
    severity: S.HIGH,
    cvss: 8.6,
    title: 'Consola interactiva de depuración o debugger expuesto en producción',
    description:
      'Se detectó una consola interactiva de depuración web (Laravel Ignition, Symfony Profiler, Werkzeug o H2 Console) accesible sin autenticación, lo que puede permitir ejecución remota de código (RCE) o fuga masiva de configuración interna.',
    recommendation:
      'Deshabilite los paquetes y rutas de depuración de desarrollo en entornos de producción (p. ej. APP_DEBUG=false en Laravel).',
  },
  {
    id: 'PATH-K8S-CONFIG-EXPOSED',
    category: C.SENSITIVE_PATH,
    severity: S.CRITICAL,
    cvss: 9.8,
    title: 'Configuración o credenciales de Kubernetes o Cloud expuestas',
    description:
      'Se detectó acceso público a archivos de configuración o credenciales de nube (como .kube/config o certificados de servicio) expuestos directamente en el servidor web.',
    recommendation:
      'Elimine inmediatamente los archivos de configuración de despliegue de los directorios públicos del servidor web y restrinja el acceso.',
  },
  // ------------------------------------------------------- vulnerabilidades (CVE)
  {
    id: 'VULN-KNOWN-CVE',
    category: C.VULNERABLE_SOFTWARE,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Versión de software con vulnerabilidades conocidas',
    description:
      'La versión del servicio detectada figura como afectada en vulnerabilidades publicadas (CVE). La severidad y el CVSS del hallazgo son los del CVE más grave.',
    recommendation: 'Actualice el software a la última versión soportada por el fabricante.',
  },
  // ------------------------------------------------------ seguridad del correo
  {
    id: 'MAIL-SPF-MISSING',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'El dominio no publica un registro SPF',
    description:
      'Sin SPF los servidores de correo no pueden comprobar qué servidores están autorizados a enviar en nombre del dominio, lo que facilita suplantarlo en campañas de phishing.',
    recommendation:
      'Publique un registro TXT con la política SPF que enumere sus servidores de envío y termine en -all (p. ej. "v=spf1 include:_spf.google.com -all").',
  },
  {
    id: 'MAIL-SPF-INVALID',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'El registro SPF no es válido',
    description:
      'Un SPF con errores (varios registros, sintaxis incorrecta o más de 10 consultas DNS) produce un error permanente (permerror) y los receptores lo ignoran: el dominio queda sin protección.',
    recommendation:
      'Deje un único registro "v=spf1", corrija los mecanismos no válidos y reduzca los include anidados por debajo de 10 consultas DNS.',
  },
  {
    id: 'MAIL-SPF-PASS-ALL',
    category: C.EMAIL_SECURITY,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'El SPF autoriza a cualquier servidor (+all)',
    description:
      'El mecanismo +all declara válido el correo enviado desde cualquier servidor de Internet, anulando la protección de SPF y haciendo creíble la suplantación.',
    recommendation: 'Sustituya +all por -all después de enumerar los servidores legítimos de envío.',
  },
  {
    id: 'MAIL-SPF-NEUTRAL',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 4.3,
    title: 'El SPF no indica qué hacer con los servidores no autorizados',
    description:
      'El registro termina en ?all o no tiene mecanismo all, así que el correo de servidores no autorizados se trata como neutral y no se rechaza.',
    recommendation: 'Termine el registro SPF en -all (o ~all mientras valida la configuración con DMARC).',
  },
  {
    id: 'MAIL-SPF-SOFTFAIL',
    category: C.EMAIL_SECURITY,
    severity: S.LOW,
    cvss: 3.1,
    title: 'El SPF solo marca como sospechoso el correo no autorizado (~all)',
    description:
      'Con ~all el correo de servidores no autorizados se acepta marcado como sospechoso. Sin una política DMARC que lo rechace, la suplantación sigue llegando a las bandejas.',
    recommendation: 'Publique DMARC con p=quarantine o p=reject, o cambie ~all por -all.',
  },
  {
    id: 'MAIL-DMARC-MISSING',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 6.1,
    title: 'El dominio no tiene política DMARC',
    description:
      'Sin DMARC los receptores no saben qué hacer con el correo que falla SPF o DKIM, y el dominio no recibe informes de quién envía en su nombre. Es la principal defensa contra la suplantación del remitente.',
    recommendation:
      'Publique un TXT en _dmarc.<dominio> empezando por "v=DMARC1; p=none; rua=mailto:..." para recibir informes y, tras revisarlos, endurezca a p=quarantine y p=reject.',
  },
  {
    id: 'MAIL-DMARC-INVALID',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'La política DMARC no es válida',
    description: 'Hay varios registros DMARC o el registro no tiene una política (p=) válida, así que los receptores lo ignoran.',
    recommendation: 'Deje un único registro "v=DMARC1; p=..." en _dmarc.<dominio> con una política none, quarantine o reject.',
  },
  {
    id: 'MAIL-DMARC-MONITOR-ONLY',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 4.3,
    title: 'DMARC solo monitoriza (p=none)',
    description:
      'Con p=none el correo que suplanta al dominio se entrega igualmente; la política solo sirve para recibir informes.',
    recommendation: 'Revise los informes DMARC, autorice los remitentes legítimos y pase a p=quarantine y después a p=reject.',
  },
  {
    id: 'MAIL-DMARC-PARTIAL',
    category: C.EMAIL_SECURITY,
    severity: S.LOW,
    cvss: 3.1,
    title: 'DMARC se aplica solo a una parte del correo (pct < 100)',
    description: 'El parámetro pct limita la política a un porcentaje de los mensajes; el resto se entrega aunque falle la autenticación.',
    recommendation: 'Elimine pct o fíjelo en 100 cuando termine la transición.',
  },
  {
    id: 'MAIL-DMARC-SUBDOMAINS-UNPROTECTED',
    category: C.EMAIL_SECURITY,
    severity: S.LOW,
    cvss: 3.1,
    title: 'Los subdominios quedan fuera de la política DMARC (sp=none)',
    description: 'La política protege el dominio principal, pero sp=none permite suplantar cualquier subdominio (p. ej. facturas.<dominio>).',
    recommendation: 'Elimine sp=none o fije sp=quarantine / sp=reject.',
  },
  {
    id: 'MAIL-DMARC-NO-REPORTS',
    category: C.EMAIL_SECURITY,
    severity: S.INFO,
    cvss: 0,
    title: 'DMARC no solicita informes (sin rua)',
    description: 'Sin la etiqueta rua no se reciben informes agregados, así que no hay visibilidad de quién envía correo en nombre del dominio.',
    recommendation: 'Añada rua=mailto:<buzón> (o el de un servicio de análisis DMARC) al registro.',
  },
  {
    id: 'MAIL-DKIM-NOT-FOUND',
    category: C.EMAIL_SECURITY,
    severity: S.LOW,
    cvss: 3.1,
    title: 'No se encontró DKIM en los selectores habituales',
    description:
      'No hay clave DKIM publicada en los selectores más comunes (Google, Microsoft 365 y otros proveedores). DKIM firma los mensajes y es necesario para que DMARC funcione cuando el correo se reenvía. Si usa un selector propio, esta comprobación no puede verlo.',
    recommendation: 'Active la firma DKIM en su proveedor de correo y publique la clave que le indique en <selector>._domainkey.<dominio>.',
  },
  {
    id: 'MAIL-DKIM-WEAK-KEY',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 5.9,
    title: 'Clave DKIM demasiado corta',
    description: 'Las claves RSA de menos de 2048 bits pueden factorizarse con recursos al alcance de un atacante, que podría firmar correos como el dominio.',
    recommendation: 'Genere una clave DKIM de 2048 bits, publíquela en un selector nuevo y retire la antigua.',
  },
  {
    id: 'EMAIL-NO-MTA-STS',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'MTA-STS no implementado o no estricto (RFC 8461)',
    description:
      'El dominio no cuenta con una política MTA-STS válida o está en modo testing/none. Sin MTA-STS, las conexiones SMTP STARTTLS pueden ser forzadas a texto plano mediante ataques Man-in-the-Middle de degradación TLS.',
    recommendation:
      'Publique el registro DNS TXT "_mta-sts.<dominio>" con "v=STSv1; id=<id>" y sirva la política en "https://mta-sts.<dominio>/.well-known/mta-sts.txt" con "mode: enforce".',
  },
  {
    id: 'EMAIL-NO-TLS-RPT',
    category: C.EMAIL_SECURITY,
    severity: S.LOW,
    cvss: 3.1,
    title: 'Reportes TLS de correo no configurados (TLS-RPT, RFC 8460)',
    description:
      'El dominio no publica un registro DNS TXT "_smtp._tls.<dominio>" para recibir reportes de degradación o fallos TLS en la entrega de correo.',
    recommendation:
      'Publique el registro DNS TXT "_smtp._tls.<dominio>" con "v=TLSRPTv1; rua=mailto:<buzon-de-reportes>".',
  },

  // ------------------------------------------------------------- DNS y DNSSEC
  {
    id: 'DNS-SUBDOMAIN-TAKEOVER',
    category: C.EXPOSED_SERVICE,
    severity: S.CRITICAL,
    cvss: 9.3,
    title: 'Riesgo Crítico de Subdomain Takeover (Secuestro de Subdominio por CNAME huérfano)',
    description:
      'El subdominio apunta mediante registro CNAME a un recurso de un proveedor cloud (AWS S3, Azure App Service, GitHub Pages, Shopify, Heroku, Vercel) que ya no existe o no ha sido reclamado. Un atacante puede registrar dicho recurso y tomar control total del subdominio.',
    recommendation:
      'Elimine inmediatamente el registro CNAME huérfano de la zona DNS o vuelva a reclamar y configurar el recurso correspondiente en el proveedor cloud.',
  },
  {
    id: 'DNS-NO-CAA',
    category: C.EMAIL_SECURITY,
    severity: S.LOW,
    cvss: 3.7,
    title: 'Registro DNS CAA no configurado (RFC 8659)',
    description:
      'El dominio no publica registros DNS CAA (Certification Authority Authorization). Sin este registro, cualquier Autoridad de Certificación pública reconocida puede emitir certificados TLS para este dominio si supera la validación.',
    recommendation:
      'Configure registros DNS CAA restringiendo la emisión a las CAs autorizadas (p. ej. issue "letsencrypt.org") y declare una dirección "iodef" para recibir notificaciones ante intentos no autorizados.',
  },
  {
    id: 'DNS-CAA-INVALID',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'Registro DNS CAA con sintaxis inválida o flags no reconocidos',
    description:
      'Los registros CAA publicados contienen banderas críticas desconocidas o errores de formato según el RFC 8659, lo que puede provocar que las CAs rechacen la emisión legítima de certificados.',
    recommendation:
      'Corrija los registros CAA asegurando que el flag crítico no utilice bits reservados y las etiquetas sean válidas (issue, issuewild, iodef).',
  },
  {
    id: 'DNS-NO-DNSSEC',
    category: C.EMAIL_SECURITY,
    severity: S.MEDIUM,
    cvss: 5.3,
    title: 'DNSSEC no habilitado en el dominio (RFC 4033)',
    description:
      'El dominio no cuenta con firmas criptográficas DNSSEC (sin registros DS en el registrador ni DNSKEY en la zona). Las respuestas DNS están expuestas a ataques de envenenamiento de caché (cache poisoning), suplantación y secuestro de tráfico.',
    recommendation:
      'Habilite DNSSEC en su registrador de dominios y proveedor DNS para firmar la zona y garantizar la integridad de todos los registros DNS del perímetro.',
  },
  {
    id: 'DNS-DNSSEC-BOGUS',
    category: C.EMAIL_SECURITY,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Cadena de confianza DNSSEC rota o inválida',
    description:
      'Se detectaron registros DNSSEC pero la validación criptográfica falló (estado BOGUS). Los resolutores recursivos con validación DNSSEC rechazarán las consultas hacia este dominio provocando fallos de resolución (SERVFAIL).',
    recommendation:
      'Sincronice de inmediato las claves DNSKEY de sus servidores de nombres autoritativos con los registros DS delegados en el registrador.',
  },
  {
    id: 'EMAIL-IP-BLACKLISTED',
    category: C.EMAIL_SECURITY,
    severity: S.HIGH,
    cvss: 7.5,
    title: 'Dirección IP de servidor de correo listada en lista negra (DNSBL)',
    description:
      'Una dirección IP asociada a los servidores de correo (MX) del dominio se encuentra listada en una lista negra de reputación (Spamhaus ZEN o SpamCop). Los proveedores y servidores de correo en Internet rechazarán los mensajes enviados por este servidor o los clasificarán como spam.',
    recommendation:
      'Identifique el motivo específico en la URL proporcionada por el proveedor DNSBL, resuelva la causa del envío abusivo o posible brecha y solicite la desclasificación (delisting) en el portal de Spamhaus o SpamCop.',
  },
  // ------------------------------------------------------------------ divulgación (RFC 9116) y marca
  {
    id: 'SEC-TXT-MISSING',
    category: C.SENSITIVE_PATH,
    severity: S.LOW,
    cvss: 2.5,
    title: 'Archivo security.txt ausente (RFC 9116)',
    description:
      'No se encontró el archivo de divulgación responsable de vulnerabilidades en /.well-known/security.txt conforme al estándar RFC 9116. Investigadores éticos carecen de un canal formal y seguro para reportar fallos de seguridad detectados en la plataforma antes de que sean explotados maliciosamente.',
    recommendation:
      'Cree el archivo /.well-known/security.txt con la directiva Contact: (correo de seguridad o URL) y Expires: vigente según el estándar RFC 9116.',
  },
  {
    id: 'SEC-TXT-EXPIRED',
    category: C.SENSITIVE_PATH,
    severity: S.MEDIUM,
    cvss: 4.5,
    title: 'Archivo security.txt vencido (RFC 9116)',
    description:
      'El archivo /.well-known/security.txt contiene una fecha de expiración en el campo Expires: que se encuentra en el pasado. Los estándares de divulgación consideran inválida una política vencida.',
    recommendation:
      'Actualice la directiva Expires: en el archivo security.txt con una fecha futura válida (máximo 1 año hacia adelante).',
  },
  {
    id: 'SEC-TXT-INVALID',
    category: C.SENSITIVE_PATH,
    severity: S.LOW,
    cvss: 3.0,
    title: 'Archivo security.txt con sintaxis o directivas requeridas incompletas',
    description:
      'El archivo /.well-known/security.txt existe pero carece de directivas obligatorias por RFC 9116 como Contact: o Expires:.',
    recommendation:
      'Asegúrese de incluir las directivas requeridas Contact: y Expires: con formato de fecha ISO 8601 en su archivo security.txt.',
  },
  {
    id: 'EMAIL-BIMI-INVALID',
    category: C.EMAIL_SECURITY,
    severity: S.LOW,
    cvss: 3.5,
    title: 'Registro BIMI con sintaxis o directiva insegura',
    description:
      'Se detectó un registro DNS BIMI (default._bimi) pero su configuración no cumple con la especificación (por ejemplo, la ubicación del logotipo no utiliza HTTPS o existen múltiples registros en el mismo selector).',
    recommendation:
      'Corrija el registro TXT de BIMI en el DNS asegurando que la etiqueta l= apunte a un archivo SVG sobre HTTPS y que no existan registros duplicados.',
  },
];

export function computeRuleEffortAndImpact(r: {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  effort?: RemediationEffort;
  estimatedMinutes?: number;
  businessImpact?: string;
}): { effort: RemediationEffort; estimatedMinutes: number; businessImpact: string } {
  if (r.effort && r.estimatedMinutes && r.businessImpact) {
    return { effort: r.effort, estimatedMinutes: r.estimatedMinutes, businessImpact: r.businessImpact };
  }

  const isQuickWin =
    (r.id.startsWith('HDR-') && r.id !== 'HDR-CSP-MISSING') ||
    r.id.startsWith('SEC-TXT-') ||
    r.id === 'CMS-WP-XMLRPC-ENABLED' ||
    r.id === 'CMS-WP-USER-ENUMERATION' ||
    r.id === 'WAF-MISSING' ||
    r.id === 'WEB-SOURCEMAPS-EXPOSED' ||
    r.id === 'WEB-CORS-REFLECTION' ||
    r.id === 'WEB-FORM-HTTP-TARGET' ||
    r.id === 'EMAIL-BIMI-INVALID' ||
    r.id.startsWith('PORT-') ||
    r.id.startsWith('SVC-CLEARTEXT') ||
    (r.id.startsWith('PATH-') && !r.id.includes('ADMIN')) ||
    r.id === 'MAIL-SPF-MISSING' ||
    r.id === 'MAIL-DMARC-MISSING' ||
    r.id === 'MAIL-DMARC-MONITOR-ONLY' ||
    r.id.includes('PUBLIC-READ') ||
    r.id.includes('PUBLIC-ACCESS');

  const isStructural =
    r.id === 'HDR-CSP-MISSING' ||
    r.id.includes('DEPRECATED') ||
    r.id.includes('OUTDATED') ||
    r.id.includes('EOL') ||
    r.id.includes('LEGACY');

  const effort: RemediationEffort = isStructural ? 'STRUCTURAL' : isQuickWin ? 'QUICK_WIN' : 'MODERATE';
  const estimatedMinutes = isStructural ? 480 : isQuickWin ? 20 : 90;

  let businessImpact = 'Riesgo de seguridad que afecta la confidencialidad e integridad del activo.';
  if (r.id.includes('PAYMENT') || r.id.includes('SRI') || r.id.includes('Magecart') || r.id.includes('CARD')) {
    businessImpact = 'Riesgo de fraude financiero, manipulación del checkout o multas por incumplimiento PCI-DSS.';
  } else if (r.id.includes('ADMIN') || r.id.includes('LOGIN') || r.id.includes('XMLRPC') || r.id.includes('USER-ENUMERATION')) {
    businessImpact = 'Riesgo de toma de control administrativo de la tienda online y acceso no autorizado a pedidos.';
  } else if (r.category === FindingCategory.EMAIL_SECURITY || r.id.includes('MAIL') || r.id.includes('DMARC') || r.id.includes('SPF') || r.id.includes('BIMI')) {
    businessImpact = 'Riesgo de suplantación de identidad (phishing/BEC) hacia clientes o desvío de pagos con facturas falsas.';
  } else if (r.id.includes('SECRET') || r.id.includes('ENV') || r.id.includes('SOURCEMAP') || r.id.includes('KEY')) {
    businessImpact = 'Exfiltración de credenciales maestras y propiedad intelectual para acceso directo a bases de datos.';
  } else if (r.category === FindingCategory.EXPOSED_SERVICE) {
    businessImpact = 'Exposición perimetral directa a Internet que facilita ataques de fuerza bruta y explotación remota.';
  }

  return { effort, estimatedMinutes, businessImpact };
}

const enrichedRules: FindingRule[] = rawRules.map((r) => {
  const meta = computeRuleEffortAndImpact(r);
  return {
    ...r,
    effort: r.effort ?? meta.effort,
    estimatedMinutes: r.estimatedMinutes ?? meta.estimatedMinutes,
    businessImpact: r.businessImpact ?? meta.businessImpact,
  };
});

export const FINDING_RULES: ReadonlyMap<string, FindingRule> = new Map(
  enrichedRules.map((r) => [r.id, r] as const),
);

export function getRule(id: string): FindingRule {
  const rule = FINDING_RULES.get(id);
  if (!rule) {
    throw new Error(`Regla de hallazgo desconocida: ${id}`);
  }
  return rule;
}

/** Devuelve la severidad que corresponde a una puntuación CVSS v3.1. */
export function severityFromCvss(score: number): FindingSeverity {
  if (score >= 9) return S.CRITICAL;
  if (score >= 7) return S.HIGH;
  if (score >= 4) return S.MEDIUM;
  if (score > 0) return S.LOW;
  return S.INFO;
}
