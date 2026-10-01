import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { UpdateOrganizationDto } from './dto/update-organization.dto';

@Injectable()
export class OrganizationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async findMine(organizationId: string) {
    const org = await this.prisma.organization.findUnique({
      where: { id: organizationId },
      include: {
        _count: { select: { users: true, assets: true, scans: true } },
      },
    });
    if (!org) {
      throw new NotFoundException('Organización no encontrada');
    }
    return org;
  }

  async update(actor: AuthUser, dto: UpdateOrganizationDto) {
    const organizationId = actor.organizationId;
    const updated = await this.prisma.organization.update({
      where: { id: organizationId },
      data: { name: dto.name },
    });
    this.audit.record({
      organizationId,
      action: 'organization.update',
      actor,
      target: { type: 'organization', id: organizationId, label: updated.name },
      detail: { name: dto.name },
    });
    return updated;
  }

  /** Genera un slug URL-safe único a partir del nombre de la organización. */
  async generateUniqueSlug(name: string): Promise<string> {
    const base =
      name
        .normalize('NFD')
        .replace(/[̀-ͯ]/g, '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 60) || 'org';

    let slug = base;
    let attempt = 1;
    while (await this.prisma.organization.findUnique({ where: { slug }, select: { id: true } })) {
      attempt += 1;
      slug = `${base}-${attempt}`;
    }
    return slug;
  }
}
