import { IsEnum, IsOptional, IsUUID } from 'class-validator';
import { DiagnosticProfile } from '@prisma/client';

export class StartDiagnosticDto {
  @IsOptional()
  @IsEnum(DiagnosticProfile, {
    message: 'El perfil debe ser COMMERCE_360, PERIMETER_FAST o FULL_AUDIT',
  })
  profile?: DiagnosticProfile;
}

export class PostureDiffQuery {
  @IsOptional()
  @IsUUID('4', { message: 'fromBatchId debe ser un UUID válido' })
  fromBatchId?: string;

  @IsOptional()
  @IsUUID('4', { message: 'toBatchId debe ser un UUID válido' })
  toBatchId?: string;
}
