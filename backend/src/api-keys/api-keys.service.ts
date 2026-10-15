import { BadRequestException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { createHash, randomBytes } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { CreateApiKeyDto, VALID_API_KEY_SCOPES } from './dto/create-api-key.dto';

const apiKeySelect = {
  id: true,
  organizationId: true,
  name: true,
  keyPrefix: true,
  scopes: true,
  isActive: true,
  expiresAt: true,
  lastUsedAt: true,
  createdAt: true,
  updatedAt: true,
  createdBy: {
    select: {
      id: true,
      fullName: true,
      email: true,
    },
  },
} satisfies Prisma.ApiKeySelect;

export type ApiKeySummary = Prisma.ApiKeyGetPayload<{ select: typeof apiKeySelect }>;

export interface CreatedApiKeyResult extends ApiKeySummary {
  /** Secreto completo en texto plano. Solo se devuelve en el momento de creación. */
  rawKey: string;
}

@Injectable()
export class ApiKeysService {
  private readonly logger = new Logger(ApiKeysService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Genera y registra una nueva llave de API para la organización del actor.
   * El token sin procesar (`rawKey`) solo se retorna en esta respuesta.
   */
  async create(actor: AuthUser, dto: CreateApiKeyDto): Promise<CreatedApiKeyResult> {
    let expiresAt: Date | null = null;
    if (dto.expiresAt) {
      expiresAt = new Date(dto.expiresAt);
      if (isNaN(expiresAt.getTime())) {
        throw new BadRequestException('La fecha de caducidad no es válida');
      }
      if (expiresAt <= new Date()) {
        throw new BadRequestException('La fecha de caducidad debe ser futura');
      }
    }

    const scopes =
      dto.scopes && dto.scopes.length > 0
        ? Array.from(new Set(dto.scopes))
        : [...VALID_API_KEY_SCOPES];

    // Valida que los scopes pertenezcan al catálogo permitido
    for (const scope of scopes) {
      if (!VALID_API_KEY_SCOPES.includes(scope as (typeof VALID_API_KEY_SCOPES)[number])) {
        throw new BadRequestException(`El permiso "${scope}" no es válido`);
      }
    }

    // Formato de secreto: sspm_live_ + 48 caracteres hexadecimales
    const rawEntropy = randomBytes(24).toString('hex');
    const rawKey = `sspm_live_${rawEntropy}`;
    const keyPrefix = `sspm_live_${rawEntropy.slice(0, 6)}...`;
    const keyHash = createHash('sha256').update(rawKey).digest('hex');

    const created = await this.prisma.apiKey.create({
      data: {
        organizationId: actor.organizationId,
        name: dto.name.trim(),
        keyPrefix,
        keyHash,
        scopes,
        expiresAt,
        createdById: actor.id,
      },
      select: apiKeySelect,
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'api_key.create',
      actor,
      target: { type: 'api_key', id: created.id, label: created.name },
      detail: {
        keyPrefix: created.keyPrefix,
        scopes: created.scopes,
        expiresAt: created.expiresAt ? created.expiresAt.toISOString() : null,
      },
    });

    return {
      ...created,
      rawKey,
    };
  }

  /** Lista todas las llaves de API activas o revocadas de una organización. */
  async findAll(organizationId: string): Promise<ApiKeySummary[]> {
    return this.prisma.apiKey.findMany({
      where: { organizationId },
      select: apiKeySelect,
      orderBy: { createdAt: 'desc' },
    });
  }

  /** Revoca de forma inmediata una llave de API activa. */
  async revoke(actor: AuthUser, id: string): Promise<ApiKeySummary> {
    const existing = await this.prisma.apiKey.findFirst({
      where: { id, organizationId: actor.organizationId },
      select: apiKeySelect,
    });
    if (!existing) {
      throw new NotFoundException('Llave de API no encontrada');
    }

    if (!existing.isActive) {
      return existing;
    }

    const updated = await this.prisma.apiKey.update({
      where: { id },
      data: { isActive: false },
      select: apiKeySelect,
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'api_key.revoke',
      actor,
      target: { type: 'api_key', id: updated.id, label: updated.name },
      detail: { keyPrefix: updated.keyPrefix },
    });

    return updated;
  }

  /** Elimina definitivamente una llave de API. */
  async remove(actor: AuthUser, id: string): Promise<{ success: boolean }> {
    const existing = await this.prisma.apiKey.findFirst({
      where: { id, organizationId: actor.organizationId },
      select: apiKeySelect,
    });
    if (!existing) {
      throw new NotFoundException('Llave de API no encontrada');
    }

    await this.prisma.apiKey.delete({
      where: { id },
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'api_key.delete',
      actor,
      target: { type: 'api_key', id: existing.id, label: existing.name },
      detail: { keyPrefix: existing.keyPrefix },
    });

    return { success: true };
  }

  /**
   * Valida un token secreto recibido por encabezado HTTP.
   * Devuelve la entidad de la llave y los datos de su tenant si está activa y vigente.
   */
  async validateApiKey(rawKey: string): Promise<{
    id: string;
    organizationId: string;
    name: string;
    scopes: string[];
  } | null> {
    if (!rawKey || typeof rawKey !== 'string') {
      return null;
    }

    const trimmed = rawKey.trim();
    if (!trimmed.startsWith('sspm_live_') || trimmed.length < 30) {
      return null;
    }

    const keyHash = createHash('sha256').update(trimmed).digest('hex');

    const key = await this.prisma.apiKey.findUnique({
      where: { keyHash },
      include: {
        organization: {
          select: { id: true, isActive: true },
        },
      },
    });

    if (!key || !key.isActive || !key.organization.isActive) {
      return null;
    }

    if (key.expiresAt && key.expiresAt.getTime() <= Date.now()) {
      return null;
    }

    // Actualiza lastUsedAt de forma asíncrona
    this.prisma.apiKey
      .update({
        where: { id: key.id },
        data: { lastUsedAt: new Date() },
      })
      .catch((err: Error) => {
        this.logger.warn(`No se pudo actualizar lastUsedAt para apiKey ${key.id}: ${err.message}`);
      });

    return {
      id: key.id,
      organizationId: key.organizationId,
      name: key.name,
      scopes: key.scopes,
    };
  }
}
