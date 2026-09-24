import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEmail, IsString, Matches, MaxLength, MinLength } from 'class-validator';

/**
 * Registro inicial de un tenant: crea la organización y su primer usuario
 * con rol ADMIN en una misma transacción.
 */
export class RegisterDto {
  @ApiProperty({ example: 'Acme S.A.S.', description: 'Nombre de la organización (tenant)' })
  @IsString()
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  @MinLength(2)
  @MaxLength(150)
  organizationName: string;

  @ApiProperty({ example: 'Ana Pérez' })
  @IsString()
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  @MinLength(2)
  @MaxLength(150)
  fullName: string;

  @ApiProperty({ example: 'ana@acme.com' })
  @IsEmail()
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @MaxLength(255)
  email: string;

  @ApiProperty({
    example: 'Sup3rSecreta!',
    description: 'Mínimo 8 caracteres, con al menos una letra y un número',
  })
  @IsString()
  @MinLength(8)
  @MaxLength(72)
  @Matches(/^(?=.*[A-Za-z])(?=.*\d).+$/, {
    message: 'La contraseña debe contener al menos una letra y un número',
  })
  password: string;
}
