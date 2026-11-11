import { IsOptional, IsString } from 'class-validator';

export class RemediationAdviceDto {
  @IsOptional()
  @IsString()
  customContext?: string;
}
