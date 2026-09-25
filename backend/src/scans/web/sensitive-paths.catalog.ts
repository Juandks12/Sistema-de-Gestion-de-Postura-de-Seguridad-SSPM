/**
 * Catálogo de rutas sensibles (RF-06). Cada entrada define una firma sobre el
 * cuerpo o las cabeceras de la respuesta para reducir falsos positivos: un 200
 * sin firma no basta, ya que muchos sitios responden 200 a cualquier ruta.
 *
 * La evidencia guardada nunca incluye el contenido del archivo (puede contener secretos).
 */
export interface SensitivePathRule {
  path: string;
  ruleId: string;
  /** Descripción corta para el título del hallazgo. */
  label: string;
  /** Firma que debe cumplir la respuesta para considerarla positiva. */
  signature: (ctx: PathResponse) => boolean;
}

export interface PathResponse {
  status: number;
  contentType: string;
  body: Buffer;
  text: string;
}

const text = (re: RegExp) => (r: PathResponse) => re.test(r.text);
const magic = (bytes: number[]) => (r: PathResponse) =>
  r.body.length >= bytes.length && bytes.every((b, i) => r.body[i] === b);
const html = (r: PathResponse) => /text\/html/i.test(r.contentType);

const DOTENV_RE = /^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*\S/m;
const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/;
const SQL_DUMP_RE = /(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|PostgreSQL database dump)/i;
const DIRECTORY_LISTING_RE = /<title>\s*Index of \/|Directory listing for \//i;

export const SENSITIVE_PATHS: SensitivePathRule[] = [
  // Secretos
  { path: '/.env', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Archivo .env', signature: text(DOTENV_RE) },
  { path: '/.env.production', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Archivo .env.production', signature: text(DOTENV_RE) },
  { path: '/.env.local', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Archivo .env.local', signature: text(DOTENV_RE) },
  { path: '/.aws/credentials', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Credenciales de AWS', signature: text(/\[default\]|aws_secret_access_key/i) },
  { path: '/.ssh/id_rsa', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Clave privada SSH', signature: text(PRIVATE_KEY_RE) },
  { path: '/id_rsa', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Clave privada SSH', signature: text(PRIVATE_KEY_RE) },
  { path: '/.htpasswd', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Archivo .htpasswd', signature: text(/^[^:\s]+:\$?(?:apr1|2y|2a|1)?\$?[^\s]+$/m) },
  { path: '/wp-config.php.bak', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Copia de wp-config.php', signature: text(/DB_PASSWORD|DB_USER/) },
  { path: '/config.php.bak', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Copia de config.php', signature: text(/password|passwd|secret/i) },
  { path: '/.npmrc', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Archivo .npmrc con token', signature: text(/_authToken\s*=/) },
  { path: '/.docker/config.json', ruleId: 'PATH-SECRETS-EXPOSED', label: 'Credenciales de Docker', signature: text(/"auths"\s*:/) },

  // Control de versiones
  { path: '/.git/HEAD', ruleId: 'PATH-VCS-EXPOSED', label: 'Directorio .git', signature: text(/^ref:\s*refs\//) },
  { path: '/.git/config', ruleId: 'PATH-VCS-EXPOSED', label: 'Configuración de .git', signature: text(/\[core\]/) },
  { path: '/.svn/entries', ruleId: 'PATH-VCS-EXPOSED', label: 'Directorio .svn', signature: text(/^\d+\s*$/m) },
  { path: '/.svn/wc.db', ruleId: 'PATH-VCS-EXPOSED', label: 'Base de datos de .svn', signature: text(/^SQLite format 3/) },
  { path: '/.hg/requires', ruleId: 'PATH-VCS-EXPOSED', label: 'Directorio .hg', signature: text(/revlogv1|store/) },

  // Copias de seguridad
  { path: '/backup.sql', ruleId: 'PATH-BACKUP-EXPOSED', label: 'Volcado SQL', signature: text(SQL_DUMP_RE) },
  { path: '/dump.sql', ruleId: 'PATH-BACKUP-EXPOSED', label: 'Volcado SQL', signature: text(SQL_DUMP_RE) },
  { path: '/db.sql', ruleId: 'PATH-BACKUP-EXPOSED', label: 'Volcado SQL', signature: text(SQL_DUMP_RE) },
  { path: '/database.sql', ruleId: 'PATH-BACKUP-EXPOSED', label: 'Volcado SQL', signature: text(SQL_DUMP_RE) },
  { path: '/backup.zip', ruleId: 'PATH-BACKUP-EXPOSED', label: 'Archivo ZIP de respaldo', signature: magic([0x50, 0x4b, 0x03, 0x04]) },
  { path: '/backup.tar.gz', ruleId: 'PATH-BACKUP-EXPOSED', label: 'Archivo tar.gz de respaldo', signature: magic([0x1f, 0x8b]) },
  { path: '/site.zip', ruleId: 'PATH-BACKUP-EXPOSED', label: 'Archivo ZIP del sitio', signature: magic([0x50, 0x4b, 0x03, 0x04]) },
  { path: '/www.zip', ruleId: 'PATH-BACKUP-EXPOSED', label: 'Archivo ZIP del sitio', signature: magic([0x50, 0x4b, 0x03, 0x04]) },

  // Configuración
  { path: '/.htaccess', ruleId: 'PATH-CONFIG-EXPOSED', label: 'Archivo .htaccess', signature: text(/RewriteEngine|RewriteRule|AuthType|<Files/i) },
  { path: '/web.config', ruleId: 'PATH-CONFIG-EXPOSED', label: 'Archivo web.config', signature: text(/<configuration>|<system\.web/i) },
  { path: '/config.json', ruleId: 'PATH-CONFIG-EXPOSED', label: 'Archivo config.json', signature: text(/"(password|secret|apiKey|api_key|token|connectionString)"\s*:/i) },
  { path: '/appsettings.json', ruleId: 'PATH-CONFIG-EXPOSED', label: 'Archivo appsettings.json', signature: text(/ConnectionStrings|"Logging"/) },
  { path: '/.DS_Store', ruleId: 'PATH-CONFIG-EXPOSED', label: 'Archivo .DS_Store', signature: magic([0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31]) },
  { path: '/composer.json', ruleId: 'PATH-CONFIG-EXPOSED', label: 'Archivo composer.json', signature: text(/"require"\s*:/) },
  { path: '/package.json', ruleId: 'PATH-CONFIG-EXPOSED', label: 'Archivo package.json', signature: text(/"(dependencies|devDependencies|scripts)"\s*:/) },

  // Diagnóstico
  { path: '/phpinfo.php', ruleId: 'PATH-DEBUG-INFO', label: 'phpinfo()', signature: text(/PHP Version|phpinfo\(\)/) },
  { path: '/info.php', ruleId: 'PATH-DEBUG-INFO', label: 'phpinfo()', signature: text(/PHP Version|phpinfo\(\)/) },
  { path: '/server-status', ruleId: 'PATH-DEBUG-INFO', label: 'Apache server-status', signature: text(/Apache Server Status/) },
  { path: '/server-info', ruleId: 'PATH-DEBUG-INFO', label: 'Apache server-info', signature: text(/Apache Server Information/) },
  { path: '/actuator', ruleId: 'PATH-DEBUG-INFO', label: 'Spring Boot Actuator', signature: text(/"_links"\s*:/) },
  { path: '/actuator/env', ruleId: 'PATH-DEBUG-INFO', label: 'Actuator /env', signature: text(/propertySources|activeProfiles/) },
  { path: '/actuator/heapdump', ruleId: 'PATH-DEBUG-INFO', label: 'Actuator heapdump', signature: (r) => r.status === 200 && /octet-stream/i.test(r.contentType) },
  { path: '/elmah.axd', ruleId: 'PATH-DEBUG-INFO', label: 'ELMAH', signature: text(/Error Log for/i) },
  { path: '/trace.axd', ruleId: 'PATH-DEBUG-INFO', label: 'ASP.NET trace', signature: text(/Application Trace/i) },
  { path: '/debug/pprof/', ruleId: 'PATH-DEBUG-INFO', label: 'Go pprof', signature: text(/Types of profiles available/) },
  { path: '/_profiler/', ruleId: 'PATH-DEBUG-INFO', label: 'Symfony profiler', signature: text(/Symfony Profiler/i) },
  { path: '/telescope', ruleId: 'PATH-DEBUG-INFO', label: 'Laravel Telescope', signature: text(/Telescope/) },
  { path: '/console', ruleId: 'PATH-DEBUG-INFO', label: 'Consola web (H2/Werkzeug)', signature: text(/H2 Console|Werkzeug Debugger|Interactive Console/i) },

  // Listado de directorios
  { path: '/uploads/', ruleId: 'PATH-DIRECTORY-LISTING', label: '/uploads/', signature: text(DIRECTORY_LISTING_RE) },
  { path: '/backup/', ruleId: 'PATH-DIRECTORY-LISTING', label: '/backup/', signature: text(DIRECTORY_LISTING_RE) },
  { path: '/static/', ruleId: 'PATH-DIRECTORY-LISTING', label: '/static/', signature: text(DIRECTORY_LISTING_RE) },
  { path: '/assets/', ruleId: 'PATH-DIRECTORY-LISTING', label: '/assets/', signature: text(DIRECTORY_LISTING_RE) },
  { path: '/images/', ruleId: 'PATH-DIRECTORY-LISTING', label: '/images/', signature: text(DIRECTORY_LISTING_RE) },

  // Paneles de administración
  { path: '/phpmyadmin/', ruleId: 'PATH-ADMIN-PANEL', label: 'phpMyAdmin', signature: text(/phpMyAdmin/) },
  { path: '/pma/', ruleId: 'PATH-ADMIN-PANEL', label: 'phpMyAdmin', signature: text(/phpMyAdmin/) },
  { path: '/adminer.php', ruleId: 'PATH-ADMIN-PANEL', label: 'Adminer', signature: text(/Adminer/) },
  { path: '/wp-login.php', ruleId: 'PATH-ADMIN-PANEL', label: 'WordPress wp-login', signature: (r) => html(r) && /wp-login|wordpress/i.test(r.text) },
  { path: '/administrator/', ruleId: 'PATH-ADMIN-PANEL', label: 'Joomla administrator', signature: text(/Joomla/i) },
  { path: '/admin/', ruleId: 'PATH-ADMIN-PANEL', label: '/admin/', signature: (r) => html(r) && /<input[^>]+type=["']?password/i.test(r.text) },
  { path: '/manager/html', ruleId: 'PATH-ADMIN-PANEL', label: 'Tomcat Manager', signature: (r) => r.status === 401 || /Tomcat Web Application Manager/i.test(r.text) },

  // Documentación de API
  { path: '/swagger.json', ruleId: 'PATH-API-DOCS', label: 'swagger.json', signature: text(/"(swagger|openapi)"\s*:/) },
  { path: '/openapi.json', ruleId: 'PATH-API-DOCS', label: 'openapi.json', signature: text(/"openapi"\s*:/) },
  { path: '/v2/api-docs', ruleId: 'PATH-API-DOCS', label: 'Springfox api-docs', signature: text(/"(swagger|openapi)"\s*:/) },
  { path: '/swagger-ui/', ruleId: 'PATH-API-DOCS', label: 'Swagger UI', signature: text(/swagger-ui/i) },
  { path: '/api/docs', ruleId: 'PATH-API-DOCS', label: 'Swagger UI', signature: text(/swagger-ui|redoc/i) },
  { path: '/graphql', ruleId: 'PATH-API-DOCS', label: 'GraphQL', signature: text(/GraphiQL|"errors"\s*:\s*\[/i) },
];
