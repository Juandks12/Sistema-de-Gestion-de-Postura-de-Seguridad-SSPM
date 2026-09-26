import { plainToInstance } from 'class-transformer';
import { Transform } from 'class-transformer';
import {
  IsBoolean,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  Max,
  Min,
  MinLength,
  validateSync,
} from 'class-validator';

export enum NodeEnv {
  Development = 'development',
  Test = 'test',
  Production = 'production',
}

class EnvironmentVariables {
  @IsEnum(NodeEnv)
  @IsOptional()
  NODE_ENV: NodeEnv = NodeEnv.Development;

  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
  PORT: number = 3000;

  @IsString()
  @MinLength(1)
  DATABASE_URL!: string;

  @IsString()
  @MinLength(16, { message: 'JWT_SECRET debe tener al menos 16 caracteres' })
  JWT_SECRET!: string;

  @IsString()
  @IsOptional()
  JWT_EXPIRES_IN: string = '8h';

  @IsInt()
  @Min(4)
  @Max(15)
  @IsOptional()
  BCRYPT_SALT_ROUNDS: number = 12;

  @IsString()
  @IsOptional()
  CORS_ORIGINS: string = '';

  // ------------------------------------------------------------------
  // Motor de escaneo (Nmap)
  // ------------------------------------------------------------------

  /** Ruta o nombre del binario de Nmap. */
  @IsString()
  @IsOptional()
  NMAP_PATH: string = 'nmap';

  /** Activa el worker que procesa la cola de escaneos en este proceso. */
  @Transform(({ obj, key }) => toBoolean((obj as Record<string, unknown>)[key]))
  @IsBoolean()
  @IsOptional()
  SCAN_WORKER_ENABLED: boolean = true;

  /** Escaneos simultáneos máximos en esta instancia. */
  @IsInt()
  @Min(1)
  @Max(20)
  @IsOptional()
  SCAN_MAX_CONCURRENCY: number = 2;

  /** Escaneos simultáneos máximos por organización (protección contra abuso). */
  @IsInt()
  @Min(1)
  @Max(10)
  @IsOptional()
  SCAN_MAX_CONCURRENCY_PER_ORG: number = 1;

  /** Escaneos que una organización puede solicitar por hora. */
  @IsInt()
  @Min(1)
  @Max(1000)
  @IsOptional()
  SCAN_MAX_PER_HOUR_PER_ORG: number = 30;

  /** Tiempo máximo de un escaneo antes de abortarlo (RNF-02). */
  @IsInt()
  @Min(30)
  @Max(3600)
  @IsOptional()
  SCAN_TIMEOUT_SECONDS: number = 600;

  /** Intervalo con el que el worker revisa la cola. */
  @IsInt()
  @Min(500)
  @Max(60000)
  @IsOptional()
  SCAN_POLL_INTERVAL_MS: number = 5000;

  /** Número de puertos más comunes a escanear (--top-ports). Ignorado si SCAN_PORTS está definido. */
  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
  SCAN_TOP_PORTS: number = 1000;

  /** Lista explícita de puertos/rangos (p. ej. "22,80,443,8000-8100"). Vacío = usar SCAN_TOP_PORTS. */
  @IsString()
  @Matches(/^$|^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$/, {
    message: 'SCAN_PORTS debe ser una lista de puertos o rangos separados por coma',
  })
  @IsOptional()
  SCAN_PORTS: string = '';

  /** Plantilla de temporización de Nmap (-T0 a -T5). */
  @IsInt()
  @Min(0)
  @Max(5)
  @IsOptional()
  SCAN_TIMING_TEMPLATE: number = 4;

  /** Puertos HTTP a auditar además de los detectados por el escaneo de puertos. */
  @IsString()
  @Matches(/^[0-9]{1,5}(,[0-9]{1,5})*$/, { message: 'WEB_HTTP_PORTS debe ser una lista de puertos separados por coma' })
  @IsOptional()
  WEB_HTTP_PORTS: string = '80';

  /** Puertos HTTPS a auditar además de los detectados por el escaneo de puertos. */
  @IsString()
  @Matches(/^[0-9]{1,5}(,[0-9]{1,5})*$/, { message: 'WEB_HTTPS_PORTS debe ser una lista de puertos separados por coma' })
  @IsOptional()
  WEB_HTTPS_PORTS: string = '443';

  /** Tiempo máximo por petición HTTP/TLS durante la auditoría web. */
  @IsInt()
  @Min(1000)
  @Max(120000)
  @IsOptional()
  WEB_REQUEST_TIMEOUT_MS: number = 10000;

  /** Peticiones simultáneas al comprobar rutas sensibles. */
  @IsInt()
  @Min(1)
  @Max(16)
  @IsOptional()
  WEB_PATHS_CONCURRENCY: number = 4;

  /**
   * Modo laboratorio: permite registrar y escanear IPs privadas/loopback.
   * Solo para el caso de estudio con activos controlados (sección 13.5).
   * NUNCA activar en producción.
   */
  @Transform(({ obj, key }) => toBoolean((obj as Record<string, unknown>)[key]))
  @IsBoolean()
  @IsOptional()
  ALLOW_PRIVATE_TARGETS: boolean = false;

  // ------------------------------------------------------------------
  // Monitoreo continuo (sección 10.4)
  // ------------------------------------------------------------------

  /** Activa el planificador que encola auditorías periódicas en este proceso. */
  @Transform(({ obj, key }) => toBoolean((obj as Record<string, unknown>)[key]))
  @IsBoolean()
  @IsOptional()
  SCHEDULER_ENABLED: boolean = true;

  /** Cada cuánto revisa el planificador qué activos toca reauditar. */
  @IsInt()
  @Min(1000)
  @Max(3600000)
  @IsOptional()
  SCHEDULER_INTERVAL_MS: number = 60000;

  /** Activos que se encolan como máximo en cada revisión del planificador. */
  @IsInt()
  @Min(1)
  @Max(500)
  @IsOptional()
  SCHEDULER_BATCH_SIZE: number = 20;

  // ------------------------------------------------------------------
  // Alertas (RF-10): correo y webhooks
  // ------------------------------------------------------------------

  /** URL pública de la aplicación web, usada en los enlaces de las notificaciones. */
  @IsString()
  @IsOptional()
  APP_URL: string = 'http://localhost:8080';

  /** Servidor SMTP. Vacío = los canales de correo se omiten (estado SKIPPED). */
  @IsString()
  @IsOptional()
  SMTP_HOST: string = '';

  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
  SMTP_PORT: number = 587;

  /** true = TLS implícito (puerto 465); false = STARTTLS si el servidor lo ofrece. */
  @Transform(({ obj, key }) => toBoolean((obj as Record<string, unknown>)[key]))
  @IsBoolean()
  @IsOptional()
  SMTP_SECURE: boolean = false;

  @IsString()
  @IsOptional()
  SMTP_USER: string = '';

  @IsString()
  @IsOptional()
  SMTP_PASSWORD: string = '';

  @IsString()
  @IsOptional()
  SMTP_FROM: string = 'SSPM Alertas <alertas@sspm.local>';

  /** Tiempo máximo de una notificación por webhook o correo. */
  @IsInt()
  @Min(1000)
  @Max(60000)
  @IsOptional()
  ALERT_DELIVERY_TIMEOUT_MS: number = 10000;
}

function toBoolean(value: unknown): unknown {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const v = value.trim().toLowerCase();
    if (['true', '1', 'yes', 'on'].includes(v)) return true;
    if (['false', '0', 'no', 'off', ''].includes(v)) return false;
  }
  return value;
}

export function validateEnv(config: Record<string, unknown>): EnvironmentVariables {
  const validated = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });
  const errors = validateSync(validated, { skipMissingProperties: false });
  if (validated.NODE_ENV === NodeEnv.Production && validated.ALLOW_PRIVATE_TARGETS) {
    throw new Error('ALLOW_PRIVATE_TARGETS no puede activarse con NODE_ENV=production');
  }
  if (errors.length > 0) {
    const details = errors
      .map((e) => Object.values(e.constraints ?? {}).join(', '))
      .join('; ');
    throw new Error(`Configuración de entorno inválida: ${details}`);
  }
  return validated;
}
