import { ApiPropertyOptional } from '@nestjs/swagger';
import { ScanType } from '@prisma/client';
import { IsEnum, IsOptional } from 'class-validator';

export class CreateScanDto {
  @ApiPropertyOptional({
    enum: ScanType,
    default: ScanType.PORT_SCAN,
    description: 'PORT_SCAN (Nmap), WEB_HEADERS (cabeceras HTTP), SSL_CERT (certificado TLS) o SENSITIVE_PATHS (rutas sensibles).',
  })
  @IsOptional()
  @IsEnum(ScanType)
  type?: ScanType;
}
