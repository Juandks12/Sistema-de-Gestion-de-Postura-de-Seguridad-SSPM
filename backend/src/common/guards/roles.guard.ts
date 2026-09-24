import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRole } from '@prisma/client';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { AuthUser } from '../interfaces/auth-user.interface';

/**
 * Guard global de autorización (RBAC). Comprueba que el rol del usuario
 * autenticado esté entre los permitidos por @Roles().
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

    const { user } = context.switchToHttp().getRequest<{ user?: AuthUser }>();
    if (!user) {
      // Endpoint público con @Roles(): no hay identidad que evaluar.
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
