import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ArrayNotEmpty, IsArray, IsDateString, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

export const VALID_API_KEY_SCOPES = [
  'findings:read',
  'alerts:read',
  'posture:read',
  'assets:read',
] as const;

export type ApiKeyScope = (typeof VALID_API_KEY_SCOPES)[number];

export class CreateApiKeyDto {
  @ApiProperty({
    description: 'Nombre descriptivo de la llave (p. ej. "Splunk Forwarder", "Wazuh SIEM", "Datadog")',
    example: 'Splunk Forwarder - Producción',
    maxLength: 120,
  })
  @IsString({ message: 'El nombre debe ser una cadena de texto' })
  @MinLength(2, { message: 'El nombre debe tener al menos 2 caracteres' })
  @MaxLength(120, { message: 'El nombre no puede exceder 120 caracteres' })
  name!: string;

  @ApiPropertyOptional({
    description: 'Alcances o permisos concedidos a la llave',
    example: ['findings:read', 'alerts:read', 'posture:read', 'assets:read'],
    enum: VALID_API_KEY_SCOPES,
    isArray: true,
  })
  @IsOptional()
  @IsArray({ message: 'Los permisos deben ser una lista' })
  @ArrayNotEmpty({ message: 'Si se especifican permisos, la lista no puede estar vacía' })
  @IsString({ each: true, message: 'Cada permiso debe ser una cadena de texto' })
  scopes?: string[];

  @ApiPropertyOptional({
    description: 'Fecha de caducidad en formato ISO-8601 (opcional, null = sin caducidad)',
    example: '2027-12-31T23:59:59Z',
  })
  @IsOptional()
  @IsDateString({}, { message: 'La fecha de expiración debe ser una fecha ISO válida' })
  expiresAt?: string;
}
