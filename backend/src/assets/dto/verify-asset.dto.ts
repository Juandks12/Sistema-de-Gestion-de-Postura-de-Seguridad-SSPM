import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional } from 'class-validator';

export class VerifyAssetDto {
  @ApiPropertyOptional({ enum: ['DNS_TXT', 'HTTP_FILE'], description: 'Si se omite se prueban ambos métodos' })
  @IsOptional()
  @IsIn(['DNS_TXT', 'HTTP_FILE'])
  method?: 'DNS_TXT' | 'HTTP_FILE';
}
