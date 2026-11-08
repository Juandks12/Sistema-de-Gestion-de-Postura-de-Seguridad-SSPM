import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { MalwareArtifactType, MalwareVerdict } from '@prisma/client';
import { Type } from 'class-transformer';
import {
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
  MinLength,
} from 'class-validator';

export class AnalyzeEmailDto {
  @ApiProperty({
    description: 'Contenido crudo del correo electrónico (.eml RFC 5322 o cabeceras SMTP + cuerpo)',
  })
  @IsString()
  @MinLength(15)
  @MaxLength(500_000)
  rawContent!: string;

  @ApiPropertyOptional({ description: 'Nombre del archivo .eml o identificador del análisis' })
  @IsOptional()
  @IsString()
  @MaxLength(250)
  artifactName?: string;

  @ApiPropertyOptional({ description: 'ID del activo (dominio/IP) asociado opcionalmente' })
  @IsOptional()
  @IsUUID()
  assetId?: string;
}

export class AnalyzeFileDto {
  @ApiProperty({ description: 'Nombre original del archivo con su extensión (ej. factura_octubre.pdf.exe)' })
  @IsString()
  @MinLength(1)
  @MaxLength(250)
  fileName!: string;

  @ApiPropertyOptional({ description: 'Tipo MIME declarado (ej. application/pdf)' })
  @IsOptional()
  @IsString()
  @MaxLength(120)
  mimeType?: string;

  @ApiPropertyOptional({ description: 'Contenido del archivo codificado en Base64 (hasta 2 MB para análisis estático seguro)' })
  @IsOptional()
  @IsString()
  @MaxLength(3_000_000)
  contentBase64?: string;

  @ApiPropertyOptional({ description: 'Contenido textual o script plano si aplica' })
  @IsOptional()
  @IsString()
  @MaxLength(500_000)
  rawText?: string;

  @ApiPropertyOptional({ description: 'Hash SHA-256 precalculado (64 caracteres hex) para consulta directa en Threat Intel' })
  @IsOptional()
  @IsString()
  @MaxLength(64)
  sha256?: string;

  @ApiPropertyOptional({ description: 'ID del activo asociado opcionalmente' })
  @IsOptional()
  @IsUUID()
  assetId?: string;
}

export class AnalyzeUrlDto {
  @ApiProperty({ description: 'URL sospechosa a inspeccionar (ej. https://bancol0mbia-seguro.top/login)' })
  @IsString()
  @MinLength(4)
  @MaxLength(2000)
  url!: string;

  @ApiPropertyOptional({ description: 'ID del activo asociado opcionalmente' })
  @IsOptional()
  @IsUUID()
  assetId?: string;
}

export class PromoteAnalysisToFindingDto {
  @ApiProperty({ description: 'ID del activo del inventario al cual se asociará el hallazgo de seguridad' })
  @IsUUID()
  assetId!: string;

  @ApiPropertyOptional({ description: 'ID del usuario responsable asignado a la remediación' })
  @IsOptional()
  @IsUUID()
  assignedToId?: string;

  @ApiPropertyOptional({ description: 'Título personalizado opcional para el hallazgo' })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  customTitle?: string;
}

export class ListMalwareAnalysesQuery {
  @ApiPropertyOptional({ enum: MalwareArtifactType })
  @IsOptional()
  @IsEnum(MalwareArtifactType)
  artifactType?: MalwareArtifactType;

  @ApiPropertyOptional({ enum: MalwareVerdict })
  @IsOptional()
  @IsEnum(MalwareVerdict)
  verdict?: MalwareVerdict;

  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  assetId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(120)
  search?: string;

  @ApiPropertyOptional({ default: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page: number = 1;

  @ApiPropertyOptional({ default: 20 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  pageSize: number = 20;
}
