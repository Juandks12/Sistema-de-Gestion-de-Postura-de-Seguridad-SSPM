import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { FindingStatus } from '@prisma/client';
import { IsIn, IsOptional, IsString, MaxLength } from 'class-validator';

/** Estados que puede fijar un usuario. RESOLVED lo determina el sistema. */
export const REVIEWABLE_STATUSES = [
  FindingStatus.OPEN,
  FindingStatus.ACCEPTED,
  FindingStatus.FALSE_POSITIVE,
] as const;

export class ReviewFindingDto {
  @ApiProperty({ enum: REVIEWABLE_STATUSES, example: FindingStatus.ACCEPTED })
  @IsIn(REVIEWABLE_STATUSES)
  status!: (typeof REVIEWABLE_STATUSES)[number];

  @ApiPropertyOptional({ example: 'Puerto necesario para el proveedor de pagos; acceso restringido por firewall.' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  note?: string;
}
