import { BadRequestException, ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User, UserRole } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'node:crypto';
import { AuthUser, JwtPayload } from '../common/interfaces/auth-user.interface';
import { OrganizationsService } from '../organizations/organizations.service';
import { PrismaService } from '../prisma/prisma.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { LoginProtectionService } from './login-protection.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

export interface AuthResponse {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: string;
  user: AuthUser;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly organizations: OrganizationsService,
    private readonly loginProtection: LoginProtectionService,
  ) {}

  /**
   * Alta de un nuevo tenant: crea la organización y su primer usuario con rol ADMIN
   * dentro de una misma transacción.
   */
  async register(dto: RegisterDto): Promise<AuthResponse> {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing) {
      throw new ConflictException('Ya existe un usuario con ese correo electrónico');
    }

    const passwordHash = await this.hashPassword(dto.password);
    const slug = await this.organizations.generateUniqueSlug(dto.organizationName);

    const user = await this.prisma.$transaction(async (tx) => {
      const organization = await tx.organization.create({
        data: { name: dto.organizationName, slug, verificationToken: randomBytes(16).toString('hex') },
      });
      return tx.user.create({
        data: {
          email: dto.email,
          fullName: dto.fullName,
          passwordHash,
          role: UserRole.ADMIN,
          organizationId: organization.id,
        },
      });
    });

    return this.buildAuthResponse(user);
  }

  async login(dto: LoginDto): Promise<AuthResponse> {
    // Cuenta bloqueada por intentos fallidos: se responde antes de comprobar la contraseña.
    await this.loginProtection.assertNotLocked(dto.email);

    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      include: { organization: { select: { isActive: true } } },
    });

    // Se compara siempre contra un hash para no revelar si el correo existe (timing).
    const hashToCompare = user?.passwordHash ?? (await this.getDummyHash());
    const passwordOk = await bcrypt.compare(dto.password, hashToCompare);

    if (!user || !passwordOk) {
      await this.loginProtection.recordFailure(dto.email);
      throw new UnauthorizedException('Credenciales inválidas');
    }
    if (!user.isActive || !user.organization.isActive) {
      throw new UnauthorizedException('Usuario u organización inactivos');
    }

    await this.loginProtection.reset(dto.email);
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    return this.buildAuthResponse(user);
  }

  /**
   * Cambio de contraseña del propio usuario. Exige la contraseña actual, cierra
   * todas las sesiones abiertas (incrementa tokenVersion) y devuelve un token
   * nuevo para que la sesión actual continúe.
   *
   * Una contraseña actual incorrecta responde 400 y no 401: el 401 se reserva
   * para sesiones inválidas y el frontend lo interpreta como cierre de sesión.
   */
  async changePassword(actor: AuthUser, dto: ChangePasswordDto): Promise<AuthResponse> {
    const user = await this.prisma.user.findUnique({ where: { id: actor.id } });
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }
    if (!(await bcrypt.compare(dto.currentPassword, user.passwordHash))) {
      throw new BadRequestException('La contraseña actual no es correcta');
    }
    if (await bcrypt.compare(dto.newPassword, user.passwordHash)) {
      throw new BadRequestException('La nueva contraseña debe ser distinta de la actual');
    }
    const updated = await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash: await this.hashPassword(dto.newPassword),
        passwordChangedAt: new Date(),
        tokenVersion: { increment: 1 },
      },
    });
    return this.buildAuthResponse(updated);
  }

  hashPassword(plain: string): Promise<string> {
    const rounds = this.config.get<number>('BCRYPT_SALT_ROUNDS') ?? 12;
    return bcrypt.hash(plain, rounds);
  }

  private buildAuthResponse(user: User): AuthResponse {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      org: user.organizationId,
      ver: user.tokenVersion,
    };
    return {
      accessToken: this.jwt.sign(payload),
      tokenType: 'Bearer',
      expiresIn: this.config.get<string>('JWT_EXPIRES_IN') ?? '8h',
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        organizationId: user.organizationId,
      },
    };
  }

  /** Hash de bcrypt calculado una sola vez para igualar el tiempo de respuesta cuando el usuario no existe. */
  private dummyHash?: Promise<string>;

  private getDummyHash(): Promise<string> {
    if (!this.dummyHash) {
      this.dummyHash = this.hashPassword('no-user-dummy-password');
    }
    return this.dummyHash;
  }
}
