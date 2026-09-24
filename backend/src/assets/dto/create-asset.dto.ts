import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { Equals, IsEnum, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';
import { AssetType } from '../../generated/prisma/client';

/** RF-01: registro de un activo externo (dominio o IP) en la organización del usuario. */
export class CreateAssetDto {
  @ApiProperty({
    example: 'www.acme.com',
    description: 'Dominio (FQDN) o dirección IP pública. Sin esquema, puerto ni ruta.',
  })
  @IsString()
  @MinLength(1)
  @MaxLength(253)
  value: string;

  @ApiPropertyOptional({
    enum: AssetType,
    description: 'Tipo del activo. Si se omite se detecta automáticamente a partir del valor.',
  })
  @IsOptional()
  @IsEnum(AssetType)
  type?: AssetType;

  @ApiPropertyOptional({ example: 'Sitio corporativo' })
  @IsOptional()
  @IsString()
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  @MaxLength(150)
  label?: string;

  @ApiPropertyOptional({ example: 'Servidor web principal alojado en el proveedor X' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  description?: string;

  @ApiProperty({
    example: true,
    description:
      'Declaración de que la organización está autorizada a analizar este activo (sección 1.6.3). Debe ser true.',
  })
  @Equals(true, { message: 'Debes confirmar que tienes autorización para analizar este activo' })
  authorizationConfirmed: boolean;
}
