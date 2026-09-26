import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsEnum, IsString, Matches, MaxLength, MinLength } from 'class-validator';
import { UserRole } from '@prisma/client';
import { IsStrongPassword } from '../../common/validators/password';

const TOKEN_PATTERN = /^[a-f0-9]{64}$/;

export class ForgotPasswordDto {
  @ApiProperty({ example: 'ana@mipyme.com' })
  @IsEmail()
  @MaxLength(254)
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  email!: string;
}

export class ResetPasswordWithTokenDto {
  @ApiProperty({ description: 'Token del enlace recibido por correo' })
  @IsString()
  @Matches(TOKEN_PATTERN, { message: 'El token no es válido' })
  token!: string;

  @ApiProperty({ example: 'NuevaClave2026', description: 'Mínimo 8 caracteres, con mayúscula, minúscula y número' })
  @IsStrongPassword()
  newPassword!: string;
}

export class InviteUserDto {
  @ApiProperty({ example: 'nuevo@mipyme.com' })
  @IsEmail()
  @MaxLength(254)
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  email!: string;

  @ApiProperty({ enum: UserRole, example: UserRole.ANALYST })
  @IsEnum(UserRole)
  role!: UserRole;
}

export class AcceptInvitationDto {
  @ApiProperty({ description: 'Token del enlace de la invitación' })
  @IsString()
  @Matches(TOKEN_PATTERN, { message: 'El token no es válido' })
  token!: string;

  @ApiProperty({ example: 'Ana Pérez' })
  @IsString()
  @MinLength(2)
  @MaxLength(150)
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  fullName!: string;

  @ApiProperty({ example: 'Password123!', description: 'Mínimo 8 caracteres, con mayúscula, minúscula y número' })
  @IsStrongPassword()
  password!: string;
}

export class MfaCodeDto {
  @ApiProperty({ example: '123456', description: 'Código de 6 dígitos de la aplicación de autenticación' })
  @IsString()
  @MinLength(6)
  @MaxLength(12)
  code!: string;
}

export class MfaLoginDto extends MfaCodeDto {
  @ApiProperty({ description: 'Token intermedio devuelto por el login cuando la cuenta tiene verificación en dos pasos' })
  @IsString()
  @MaxLength(2000)
  mfaToken!: string;

  @ApiPropertyOptional({ description: 'Código de 6 dígitos o un código de recuperación (XXXXX-XXXXX)' })
  declare code: string;
}

export class DisableMfaDto extends MfaCodeDto {
  @ApiProperty({ example: 'Password123!' })
  @IsString()
  @MinLength(1)
  @MaxLength(72)
  password!: string;
}
