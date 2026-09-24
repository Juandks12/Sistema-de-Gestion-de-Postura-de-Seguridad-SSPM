import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuthService } from '../auth/auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { CreateMemberDto } from './dto/create-member.dto';

const memberSelect = {
  id: true,
  email: true,
  fullName: true,
  role: true,
  isActive: true,
  lastLoginAt: true,
  createdAt: true,
} as const;

@Injectable()
export class OrganizationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auth: AuthService,
  ) {}

  async getById(organizationId: string) {
    const organization = await this.prisma.organization.findUnique({
      where: { id: organizationId },
      include: { _count: { select: { users: true, assets: true, scans: true } } },
    });
    if (!organization) {
      throw new NotFoundException('Organización no encontrada');
    }
    return organization;
  }

  listMembers(organizationId: string) {
    return this.prisma.user.findMany({
      where: { organizationId },
      select: memberSelect,
      orderBy: { createdAt: 'asc' },
    });
  }

  async createMember(organizationId: string, dto: CreateMemberDto) {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing) {
      throw new ConflictException('Ya existe un usuario con ese correo');
    }
    const passwordHash = await this.auth.hashPassword(dto.password);
    return this.prisma.user.create({
      data: {
        organizationId,
        email: dto.email,
        fullName: dto.fullName,
        passwordHash,
        role: dto.role,
      },
      select: memberSelect,
    });
  }
}
