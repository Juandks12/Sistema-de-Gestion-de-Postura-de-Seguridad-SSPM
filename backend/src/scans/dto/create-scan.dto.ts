import { ApiPropertyOptional } from '@nestjs/swagger';
import { ScanType } from '@prisma/client';
import { IsEnum, IsOptional } from 'class-validator';

export class CreateScanDto {
  @ApiPropertyOptional({
    enum: ScanType,
    default: ScanType.PORT_SCAN,
    description:
      'PORT_SCAN (Nmap y CVE de las versiones detectadas), WEB_HEADERS (cabeceras HTTP), SSL_CERT (certificado TLS), ' +
      'SENSITIVE_PATHS (rutas sensibles), EMAIL_SECURITY (SPF, DMARC y DKIM; solo dominios) o ' +
      'SUBDOMAIN_DISCOVERY (subdominios en Certificate Transparency; solo dominios).',
  })
  @IsOptional()
  @IsEnum(ScanType)
  type?: ScanType;
}
