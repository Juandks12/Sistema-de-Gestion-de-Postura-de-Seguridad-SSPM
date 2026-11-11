import { IsEnum, IsNumber, IsOptional, IsString, Max, Min } from 'class-validator';
import { Type } from 'class-transformer';

export enum KnowledgeCategoryEnum {
  CVE = 'CVE',
  GRC_CONTROL = 'GRC_CONTROL',
  HARDENING_GUIDE = 'HARDENING_GUIDE',
  REMEDIATION_IAC = 'REMEDIATION_IAC',
}

export class RagSearchDto {
  @IsString()
  query!: string;

  @IsOptional()
  @IsEnum(KnowledgeCategoryEnum)
  category?: KnowledgeCategoryEnum;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(20)
  limit?: number = 5;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  @Max(1)
  minSimilarity?: number = 0.1;
}
