import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { UserRole } from '../../generated/prisma/client';
import { ROLES_KEY } from '../decorators/roles.decorator';
import type { AuthenticatedUser } from '../interfaces/authenticated-user.interface';

/**
 * Guard global de autorización (RBAC). Compara el rol del usuario autenticado
 * con los roles requeridos por `@Roles(...)`. El aislamiento por tenant no se
 * hace aquí sino en los servicios, que filtran siempre por `organizationId`.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[] | undefined>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest<{ user?: AuthenticatedUser }>();
    if (!user) {
      // Endpoint público sin usuario: no aplica RBAC.
      return true;
    }
    if (!requiredRoles.includes(user.role)) {
      throw new ForbiddenException(
        `Se requiere uno de los roles: ${requiredRoles.join(', ')} (rol actual: ${user.role})`,
      );
    }
    return true;
  }
}
