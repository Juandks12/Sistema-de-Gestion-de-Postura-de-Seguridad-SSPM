import { ApiProperty } from '@nestjs/swagger';
import { IsStrongPassword } from '../../common/validators/password';

export class ResetPasswordDto {
  @ApiProperty({ example: 'Temporal2026', description: 'Nueva contraseña; el usuario debería cambiarla al entrar' })
  @IsStrongPassword()
  newPassword!: string;
}
