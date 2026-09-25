import { ApiProperty } from '@nestjs/swagger';
import { IsString, MaxLength, MinLength } from 'class-validator';
import { IsStrongPassword } from '../../common/validators/password';

export class ChangePasswordDto {
  @ApiProperty({ example: 'Password123!' })
  @IsString()
  @MinLength(1)
  @MaxLength(72)
  currentPassword!: string;

  @ApiProperty({ example: 'NuevaClave2026', description: 'Mínimo 8 caracteres, con mayúscula, minúscula y número' })
  @IsStrongPassword()
  newPassword!: string;
}
