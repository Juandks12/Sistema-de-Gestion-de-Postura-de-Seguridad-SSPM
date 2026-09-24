import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { AssetType } from '@prisma/client';
import { Transform } from 'class-transformer';
import { Equals, IsBoolean, IsEnum, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

export class CreateAssetDto {
  @ApiProperty({
    example: 'scanme.nmap.org',
    description: 'Dominio (FQDN) o dirección IP pública. Se normaliza automáticamente.',
  })
  @IsString()
  @MinLength(1)
  @MaxLength(253)
  value!: string;

  @ApiPropertyOptional({
    enum: AssetType,
    description: 'Opcional: si se omite se detecta automáticamente a partir del valor.',
  })
  @IsOptional()
  @IsEnum(AssetType)
  type?: AssetType;

  @ApiPropertyOptional({ example: 'Sitio web corporativo' })
  @IsOptional()
  @IsString()
  @MaxLength(150)
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  name?: string;

  @ApiPropertyOptional({ example: 'Servidor principal alojado en proveedor X' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  description?: string;

  @ApiProperty({
    example: true,
    description:
      'Declaración de que la organización posee o está autorizada a analizar este activo (sección 1.6.3). Debe ser true.',
  })
  @IsBoolean()
  @Equals(true, { message: 'Debes confirmar que tienes autorización para analizar este activo' })
  authorizationConfirmed!: boolean;
}
