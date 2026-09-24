import { SetMetadata } from '@nestjs/common';
import { UserRole } from '@prisma/client';

export const ROLES_KEY = 'roles';

/**
 * Restringe un endpoint a los roles indicados. Si no se usa el decorador,
 * cualquier usuario autenticado puede acceder.
 */
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
