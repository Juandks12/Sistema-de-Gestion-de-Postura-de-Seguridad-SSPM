import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsEnum, IsString, Matches, MaxLength, MinLength } from 'class-validator';
import { UserRole } from '../../generated/prisma/client';

/** Alta de un usuario dentro de la organización del administrador autenticado. */
export class CreateMemberDto {
  @ApiProperty({ example: 'Luis Gómez' })
  @IsString()
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  @MinLength(2)
  @MaxLength(150)
  fullName: string;

  @ApiProperty({ example: 'luis@acme.com' })
  @IsEmail()
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @MaxLength(255)
  email: string;

  @ApiProperty({ example: 'Temporal123' })
  @IsString()
  @MinLength(8)
  @MaxLength(72)
  @Matches(/^(?=.*[A-Za-z])(?=.*\d).+$/, {
    message: 'La contraseña debe contener al menos una letra y un número',
  })
  password: string;

  @ApiProperty({ enum: UserRole, example: UserRole.ANALYST })
  @IsEnum(UserRole)
  role: UserRole;
}
