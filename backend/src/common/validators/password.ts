import { applyDecorators } from '@nestjs/common';
import { IsString, Matches, MaxLength, MinLength } from 'class-validator';

/** Política de contraseñas del sistema (sección 11.1 del documento). */
export const PASSWORD_MIN_LENGTH = 8;
/** bcrypt solo usa los primeros 72 bytes. */
export const PASSWORD_MAX_LENGTH = 72;
export const PASSWORD_PATTERN = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/;
export const PASSWORD_RULE_MESSAGE = 'La contraseña debe incluir mayúscula, minúscula y número';

/** Aplica la política de contraseñas a una propiedad de un DTO. */
export function IsStrongPassword() {
  return applyDecorators(
    IsString(),
    MinLength(PASSWORD_MIN_LENGTH, { message: `La contraseña debe tener al menos ${PASSWORD_MIN_LENGTH} caracteres` }),
    MaxLength(PASSWORD_MAX_LENGTH),
    Matches(PASSWORD_PATTERN, { message: PASSWORD_RULE_MESSAGE }),
  );
}
