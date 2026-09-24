import { SetMetadata } from '@nestjs/common';
import type { UserRole } from '../../generated/prisma/client';

export const ROLES_KEY = 'roles';

/**
 * Restringe un endpoint a los roles indicados. Si no se declara, cualquier
 * usuario autenticado de la organización puede acceder.
 */
export const Roles = (...roles: UserRole[]): MethodDecorator & ClassDecorator =>
  SetMetadata(ROLES_KEY, roles);
