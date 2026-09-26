import { FindingCategory, FindingSeverity } from '@prisma/client';

/**
 * Catálogo de reglas de hallazgos (RF-08).
 *
 * La severidad sigue los rangos de CVSS v3.1 (sección 6.3.3 del documento):
 *   CRITICAL 9.0-10.0 | HIGH 7.0-8.9 | MEDIUM 4.0-6.9 | LOW 0.1-3.9 | INFO 0.0
 * La puntuación `cvss` es una referencia asignada a cada regla según el vector
 * típico del problema; no sustituye a una evaluación CVE concreta.
 */
export interface FindingRule {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  cvss: number;
  title: string;
  description: string;
  recommendation: string;
}

const C = FindingCategory;
const S = FindingSeverity;

const rules: FindingRule[] = [
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
];

export const FINDING_RULES: ReadonlyMap<string, FindingRule> = new Map(
  rules.map((r) => [r.id, r] as const),
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
