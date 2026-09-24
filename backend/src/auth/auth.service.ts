import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'node:crypto';
import { compare, hash, hashSync } from 'bcryptjs';
import type { JwtPayload } from '../common/interfaces/authenticated-user.interface';
import type { EnvConfig } from '../config/env.validation';
import { UserRole } from '../generated/prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { slugify } from '../organizations/slug.util';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

export interface AuthResponse {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: string;
  user: {
    id: string;
    email: string;
    fullName: string;
    role: UserRole;
    organization: { id: string; name: string; slug: string };
  };
}

@Injectable()
export class AuthService {
  /** Hash de un valor aleatorio, usado para igualar tiempos de respuesta cuando el correo no existe. */
  private readonly dummyHash: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService<EnvConfig, true>,
  ) {
    this.dummyHash = hashSync(randomUUID(), this.config.get('BCRYPT_ROUNDS', { infer: true }));
  }

  async register(dto: RegisterDto): Promise<AuthResponse> {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing) {
      throw new ConflictException('Ya existe un usuario con ese correo');
    }

    const passwordHash = await this.hashPassword(dto.password);
    const slug = await this.uniqueSlug(dto.organizationName);

    const user = await this.prisma.$transaction(async (tx) => {
      const organization = await tx.organization.create({
        data: { name: dto.organizationName, slug },
      });
      return tx.user.create({
        data: {
          organizationId: organization.id,
          email: dto.email,
          fullName: dto.fullName,
          passwordHash,
          role: UserRole.ADMIN,
        },
        include: { organization: true },
      });
    });

    return this.buildAuthResponse(user);
  }

  async login(dto: LoginDto): Promise<AuthResponse> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      include: { organization: true },
    });

    // Se compara siempre contra un hash para no revelar si el correo existe (timing).
    const passwordOk = await compare(dto.password, user?.passwordHash ?? this.dummyHash);
    if (!user || !passwordOk || !user.isActive || !user.organization.isActive) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    await this.prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
    return this.buildAuthResponse(user);
  }

  async hashPassword(password: string): Promise<string> {
    return hash(password, this.config.get('BCRYPT_ROUNDS', { infer: true }));
  }

  private async uniqueSlug(name: string): Promise<string> {
    const base = slugify(name) || 'org';
    let candidate = base;
    for (
      let i = 2;
      await this.prisma.organization.findUnique({ where: { slug: candidate } });
      i++
    ) {
      candidate = `${base}-${i}`;
    }
    return candidate;
  }

  private buildAuthResponse(user: {
    id: string;
    email: string;
    fullName: string;
    role: UserRole;
    organizationId: string;
    organization: { id: string; name: string; slug: string };
  }): AuthResponse {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      organizationId: user.organizationId,
      role: user.role,
    };
    return {
      accessToken: this.jwt.sign(payload),
      tokenType: 'Bearer',
      expiresIn: this.config.get('JWT_EXPIRES_IN', { infer: true }),
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        organization: {
          id: user.organization.id,
          name: user.organization.name,
          slug: user.organization.slug,
        },
      },
    };
  }
}
