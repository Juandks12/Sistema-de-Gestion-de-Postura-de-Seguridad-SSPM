import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UpdateOrganizationDto } from './dto/update-organization.dto';

@Injectable()
export class OrganizationsService {
  constructor(private readonly prisma: PrismaService) {}

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

  update(organizationId: string, dto: UpdateOrganizationDto) {
    return this.prisma.organization.update({
      where: { id: organizationId },
      data: { name: dto.name },
    });
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
