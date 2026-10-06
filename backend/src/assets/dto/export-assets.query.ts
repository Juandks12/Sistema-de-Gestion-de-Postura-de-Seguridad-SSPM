import { ApiPropertyOptional } from '@nestjs/swagger';
import { AssetCriticality, AssetType } from '@prisma/client';
import { Transform } from 'class-transformer';
import { IsBoolean, IsEnum, IsIn, IsOptional, IsString, MaxLength } from 'class-validator';

export class ExportAssetsQuery {
  @ApiPropertyOptional({ enum: ['csv'], default: 'csv', description: 'Formato de exportación' })
  @IsOptional()
  @IsIn(['csv'])
  format?: string = 'csv';

  @ApiPropertyOptional({ enum: AssetType })
  @IsOptional()
  @IsEnum(AssetType)
  type?: AssetType;

  @ApiPropertyOptional({ enum: AssetCriticality, description: 'Filtrar por nivel de criticidad' })
  @IsOptional()
  @IsEnum(AssetCriticality)
  criticality?: AssetCriticality;

  @ApiPropertyOptional({ description: 'Filtrar por etiqueta específica' })
  @IsOptional()
  @IsString()
  tag?: string;

  @ApiPropertyOptional({ description: 'Filtrar por estado activo/inactivo' })
  @IsOptional()
  @Transform(({ value }) => (value === 'true' ? true : value === 'false' ? false : value))
  @IsBoolean()
  isActive?: boolean;

  @ApiPropertyOptional({ description: 'Búsqueda parcial por valor o nombre' })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  search?: string;
}
