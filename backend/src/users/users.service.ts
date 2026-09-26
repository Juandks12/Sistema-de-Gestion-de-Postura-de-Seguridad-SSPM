import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { AuthService } from '../auth/auth.service';
import { loginAttemptKey } from '../auth/login-protection.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateUserDto } from './dto/update-user.dto';

/** Campos públicos de un usuario (nunca se expone passwordHash). */
const userSelect = {
  id: true,
  email: true,
  fullName: true,
  role: true,
  isActive: true,
  lastLoginAt: true,
  passwordChangedAt: true,
  organizationId: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.UserSelect;

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auth: AuthService,
  ) {}

  findAll(organizationId: string) {
    return this.prisma.user.findMany({
      where: { organizationId },
      select: userSelect,
      orderBy: { createdAt: 'asc' },
    });
  }

  async findOne(organizationId: string, id: string) {
    // El filtro por organizationId garantiza el aislamiento entre tenants.
    const user = await this.prisma.user.findFirst({
      where: { id, organizationId },
      select: userSelect,
    });
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }
    return user;
  }

  async create(actor: AuthUser, dto: CreateUserDto) {
    const exists = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (exists) {
      throw new ConflictException('Ya existe un usuario con ese correo electrónico');
    }
    const passwordHash = await this.auth.hashPassword(dto.password);
    return this.prisma.user.create({
      data: {
        email: dto.email,
        fullName: dto.fullName,
        passwordHash,
        role: dto.role,
        organizationId: actor.organizationId, // siempre el tenant del administrador
      },
      select: userSelect,
    });
  }

  async update(actor: AuthUser, id: string, dto: UpdateUserDto) {
    await this.findOne(actor.organizationId, id);
    if (id === actor.id && (dto.isActive === false || (dto.role && dto.role !== actor.role))) {
      throw new BadRequestException('No puedes desactivar ni cambiar el rol de tu propia cuenta');
    }
    return this.prisma.user.update({
      where: { id },
      data: { role: dto.role, isActive: dto.isActive },
      select: userSelect,
    });
  }

  /**
   * Un ADMIN asigna una contraseña nueva a otro usuario de su organización
   * (por ejemplo, si la olvidó). Cierra todas las sesiones de ese usuario.
   * Para la propia cuenta debe usarse el cambio de contraseña, que exige la actual.
   */
  async resetPassword(actor: AuthUser, id: string, dto: ResetPasswordDto) {
    const target = await this.findOne(actor.organizationId, id);
    if (id === actor.id) {
      throw new BadRequestException('Para tu propia cuenta usa "Cambiar mi contraseña"');
    }
    // Una contraseña nueva asignada por un administrador desbloquea la cuenta.
    await this.prisma.loginAttempt.deleteMany({ where: { key: loginAttemptKey(target.email) } });
    return this.prisma.user.update({
      where: { id },
      data: {
        passwordHash: await this.auth.hashPassword(dto.newPassword),
        passwordChangedAt: new Date(),
        tokenVersion: { increment: 1 },
      },
      select: userSelect,
    });
  }
}
