import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthUser, JwtPayload } from '../../common/interfaces/auth-user.interface';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.getOrThrow<string>('JWT_SECRET'),
    });
  }

  /**
   * Se ejecuta en cada request autenticado. Recarga el usuario desde la BD
   * para que la desactivación de cuentas/organizaciones o cambios de rol
   * tengan efecto inmediato aunque el token siga vigente.
   */
  async validate(payload: JwtPayload): Promise<AuthUser> {
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      include: { organization: { select: { isActive: true } } },
    });

    if (!user || !user.isActive || !user.organization.isActive) {
      throw new UnauthorizedException('Usuario u organización inactivos');
    }
    if (user.organizationId !== payload.org) {
      throw new UnauthorizedException('Token inválido para la organización');
    }
    // Un cambio o restablecimiento de contraseña incrementa tokenVersion y cierra
    // todas las sesiones anteriores. Los tokens antiguos sin `ver` equivalen a 0.
    if ((payload.ver ?? 0) !== user.tokenVersion) {
      throw new UnauthorizedException('La sesión ha caducado; vuelve a iniciar sesión');
    }

    return {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      organizationId: user.organizationId,
    };
  }
}
