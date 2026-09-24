import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AuthUser } from '../interfaces/auth-user.interface';

/** Inyecta el usuario autenticado (resuelto por JwtStrategy) en el handler. */
export const CurrentUser = createParamDecorator(
  (data: keyof AuthUser | undefined, ctx: ExecutionContext): AuthUser | AuthUser[keyof AuthUser] => {
    const user = ctx.switchToHttp().getRequest<{ user: AuthUser }>().user;
    return data ? user[data] : user;
  },
);
