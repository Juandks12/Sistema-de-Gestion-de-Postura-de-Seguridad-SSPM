import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { clientIp } from '../common/context/request-context';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAction } from './audit-actions';
import { ListAuditQuery } from './dto/list-audit.query';

export interface AuditEvent {
  organizationId: string;
  action: AuditAction;
  /** Quién lo hizo. Nulo en acciones sin sesión (p. ej. restablecer con token). */
  actor?: Pick<AuthUser, 'id' | 'email' | 'fullName'> | null;
  /** Objeto afectado, si lo hay. */
  target?: { type: string; id?: string | null; label?: string | null };
  /** Datos adicionales legibles. Nunca secretos ni contraseñas. */
  detail?: Record<string, unknown>;
}

const auditSelect = {
  id: true,
  action: true,
  actorId: true,
  actorEmail: true,
  actorName: true,
  targetType: true,
  targetId: true,
  targetLabel: true,
  detail: true,
  ip: true,
  createdAt: true,
} satisfies Prisma.AuditLogSelect;

/**
 * Registro de auditoría (RNF-06). `record` nunca lanza ni retrasa la acción
 * auditada: un fallo al escribir la fila se registra en el log y no rompe la
 * operación de negocio.
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);
  /** Escrituras en vuelo; las pruebas esperan con flush(). */
  private readonly pending = new Set<Promise<void>>();

  constructor(private readonly prisma: PrismaService) {}

  record(event: AuditEvent): void {
    const ip = clientIp() ?? null;
    const job = this.prisma.auditLog
      .create({
        data: {
          organizationId: event.organizationId,
          action: event.action,
          actorId: event.actor?.id ?? null,
          actorEmail: event.actor?.email?.slice(0, 254) ?? null,
          actorName: event.actor?.fullName?.slice(0, 150) ?? null,
          targetType: event.target?.type ?? null,
          targetId: event.target?.id ?? null,
          targetLabel: event.target?.label?.slice(0, 253) ?? null,
          detail: (event.detail ?? undefined) as Prisma.InputJsonValue | undefined,
          ip,
        },
      })
      .then(() => undefined)
      .catch((err: Error) => {
        this.logger.error(`No se pudo registrar la acción ${event.action}: ${err.message}`);
      });
    const tracked = job.finally(() => this.pending.delete(tracked));
    this.pending.add(tracked);
  }

  /** Espera a que terminen las escrituras en vuelo (pruebas). */
  async flush(): Promise<void> {
    while (this.pending.size > 0) {
      await Promise.allSettled([...this.pending]);
    }
  }

  async findAll(organizationId: string, query: ListAuditQuery) {
    const where: Prisma.AuditLogWhereInput = {
      organizationId,
      action: query.action,
      actorId: query.actorId,
      createdAt: {
        gte: query.from ? new Date(query.from) : undefined,
        lte: query.to ? new Date(query.to) : undefined,
      },
    };
    const [items, total] = await this.prisma.$transaction([
      this.prisma.auditLog.findMany({
        where,
        select: auditSelect,
        orderBy: { createdAt: 'desc' },
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.auditLog.count({ where }),
    ]);
    return {
      items,
      meta: { total, page: query.page, pageSize: query.pageSize, totalPages: Math.max(1, Math.ceil(total / query.pageSize)) },
    };
  }
}
