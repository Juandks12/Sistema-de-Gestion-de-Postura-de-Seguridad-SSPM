import { plainToInstance, Transform } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsString,
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

// Se lee el valor crudo (`obj[key]`) porque la conversión implícita de
// class-transformer convertiría la cadena "false" en `true` antes del transform.
const toBoolean = ({ obj, key }: { obj: Record<string, unknown>; key: string }): boolean => {
  const raw = obj[key];
  return raw === true || raw === 'true' || raw === '1';
};

const toStringArray = ({ obj, key }: { obj: Record<string, unknown>; key: string }): string[] => {
  const raw = obj[key];
  return typeof raw === 'string'
    ? raw
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean)
    : [];
};

/**
 * Esquema tipado de las variables de entorno. La aplicación no arranca si
 * alguna variable obligatoria falta o es inválida (fail-fast).
 */
export class EnvConfig {
  @IsEnum(NodeEnv)
  NODE_ENV: NodeEnv = NodeEnv.Development;

  @IsInt()
  @Min(1)
  @Max(65535)
  PORT: number = 3000;

  @IsString()
  @IsNotEmpty()
  DATABASE_URL: string;

  @IsString()
  @MinLength(16, { message: 'JWT_SECRET debe tener al menos 16 caracteres' })
  JWT_SECRET: string;

  @IsString()
  @IsNotEmpty()
  JWT_EXPIRES_IN: string = '1h';

  @IsInt()
  @Min(4)
  @Max(15)
  BCRYPT_ROUNDS: number = 12;

  @Transform(toStringArray)
  @IsArray()
  @IsString({ each: true })
  CORS_ORIGINS: string[] = [];

  @Transform(toBoolean)
  @IsBoolean()
  ALLOW_PRIVATE_TARGETS: boolean = false;
}

export function validateEnv(config: Record<string, unknown>): EnvConfig {
  const validated = plainToInstance(EnvConfig, config, {
    enableImplicitConversion: true,
    exposeDefaultValues: true,
  });
  const errors = validateSync(validated, { skipMissingProperties: false, whitelist: true });
  if (errors.length > 0) {
    const details = errors
      .map((e) => `${e.property}: ${Object.values(e.constraints ?? {}).join(', ')}`)
      .join('\n');
    throw new Error(`Configuración de entorno inválida:\n${details}`);
  }
  return validated;
}
