import { ApiPropertyOptional } from '@nestjs/swagger';
import { AssetCriticality } from '@prisma/client';
import { Transform } from 'class-transformer';
import { IsArray, IsBoolean, IsEnum, IsOptional, IsString, MaxLength } from 'class-validator';

export class UpdateAssetDto {
  @ApiPropertyOptional({ example: 'Sitio web corporativo' })
  @IsOptional()
  @IsString()
  @MaxLength(150)
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  name?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  description?: string;

  @ApiPropertyOptional({ enum: AssetCriticality, description: 'Nivel de criticidad para el negocio' })
  @IsOptional()
  @IsEnum(AssetCriticality)
  criticality?: AssetCriticality;

  @ApiPropertyOptional({ type: [String], example: ['produccion', 'aws'], description: 'Etiquetas organizacionales' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @ApiPropertyOptional({ description: 'Excluir (false) o incluir (true) el activo en el monitoreo' })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
