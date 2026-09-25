import { ApiPropertyOptional } from '@nestjs/swagger';
import { ScanType } from '@prisma/client';
import { IsEnum, IsOptional } from 'class-validator';

export class CreateScanDto {
  @ApiPropertyOptional({
    enum: ScanType,
    default: ScanType.PORT_SCAN,
    description: 'Tipo de escaneo. En el Sprint 1 solo está disponible PORT_SCAN (Nmap).',
  })
  @IsOptional()
  @IsEnum(ScanType)
  type?: ScanType;
}
