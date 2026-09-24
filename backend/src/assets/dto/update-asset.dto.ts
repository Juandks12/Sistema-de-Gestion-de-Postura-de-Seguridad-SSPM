import { ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsBoolean, IsOptional, IsString, MaxLength } from 'class-validator';

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

  @ApiPropertyOptional({ description: 'Excluir (false) o incluir (true) el activo en el monitoreo' })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
