import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type {
  AuthenticatedUser,
  JwtPayload,
} from '../common/interfaces/authenticated-user.interface';
import type { EnvConfig } from '../config/env.validation';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Estrategia JWT. Además de verificar la firma, recarga al usuario desde la
 * base de datos en cada petición para que cambios de rol, desactivación de
 * cuenta o de organización surtan efecto de inmediato (no se confía ciegamente
 * en el rol embebido en el token).
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    config: ConfigService<EnvConfig, true>,
    private readonly prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get('JWT_SECRET', { infer: true }),
    });
  }

  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        fullName: true,
        role: true,
        isActive: true,
        organizationId: true,
        organization: { select: { isActive: true } },
      },
    });

    if (!user || !user.isActive || !user.organization.isActive) {
      throw new UnauthorizedException('Usuario u organización inactivos');
    }
    if (user.organizationId !== payload.organizationId) {
      // El token fue emitido para otro tenant: se rechaza.
      throw new UnauthorizedException('Token inválido para esta organización');
    }

    return {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      organizationId: user.organizationId,
      role: user.role,
    };
  }
}
