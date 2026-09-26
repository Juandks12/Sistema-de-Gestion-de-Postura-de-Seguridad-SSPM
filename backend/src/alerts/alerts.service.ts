import { BadRequestException, Injectable, Logger, NotFoundException, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AlertChannelType, FindingSeverity, Prisma, ScanStatus, ScanType } from '@prisma/client';
import { isEmail } from 'class-validator';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import type { OpenedFinding } from '../findings/findings.service';
import { PrismaService } from '../prisma/prisma.service';
import { SEVERITY_ORDER } from '../risk/scoring';
import { AlertNotifierService, DeliveryResult, parseRecipients } from './alert-notifier.service';
import { detectAlerts, diffOpenPorts, meetsThreshold, PortInfo } from './alert-rules';
import { CreateAlertChannelDto, ListAlertsQuery, UpdateAlertChannelDto } from './dto/alerts.dto';
import { maskUrl, NotificationMessage, validateWebhookUrl } from './webhook';

const MAX_RECIPIENTS = 20;

const alertSelect = {
  id: true,
  type: true,
  severity: true,
  title: true,
  message: true,
  data: true,
  deliveries: true,
  acknowledgedAt: true,
  createdAt: true,
  scanId: true,
  asset: { select: { id: true, value: true, name: true, type: true } },
  acknowledgedBy: { select: { id: true, fullName: true, email: true } },
} satisfies Prisma.AlertSelect;

const channelSelect = {
  id: true,
  type: true,
  name: true,
  target: true,
  minSeverity: true,
  isActive: true,
  lastDeliveryAt: true,
  lastDeliveryStatus: true,
  lastDeliveryError: true,
  createdAt: true,
  updatedAt: true,
  createdBy: { select: { id: true, fullName: true } },
} satisfies Prisma.AlertChannelSelect;

type ChannelRow = Prisma.AlertChannelGetPayload<{ select: typeof channelSelect }>;

export interface ScanCompletedEvent {
  organizationId: string;
  assetId: string;
  scanId: string;
  scanType: ScanType;
  opened: OpenedFinding[];
  /** Solo SUBDOMAIN_DISCOVERY: subdominios nuevos fuera del inventario (null = línea base). */
  newHosts?: string[] | null;
}

/**
 * Alertas tempranas (RF-10). Se generan al completar un escaneo, se guardan
 * para consultarlas en la plataforma y se notifican de forma asíncrona por
 * los canales activos de la organización, sin retrasar al worker de escaneos.
 */
@Injectable()
export class AlertsService implements OnApplicationShutdown {
  private readonly logger = new Logger(AlertsService.name);
  private readonly pending = new Set<Promise<void>>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly notifier: AlertNotifierService,
    private readonly audit: AuditService,
  ) {}

  async onApplicationShutdown(): Promise<void> {
    await Promise.allSettled([...this.pending]);
  }

  private get allowPrivate(): boolean {
    return this.config.get<boolean>('ALLOW_PRIVATE_TARGETS') === true;
  }

  private appUrl(path: string): string {
    const base = (this.config.get<string>('APP_URL') ?? '').replace(/\/+$/, '');
    return `${base}${path}`;
  }

  /** Espera a que terminen las notificaciones en curso (usado en pruebas y al apagar). */
  async flush(): Promise<void> {
    while (this.pending.size > 0) {
      await Promise.allSettled([...this.pending]);
    }
  }

  private track(job: Promise<void>): void {
    const tracked = job
      .catch((err: unknown) => this.logger.error(`Error enviando notificaciones: ${(err as Error).message}`))
      .finally(() => this.pending.delete(tracked));
    this.pending.add(tracked);
  }

  // ---------------------------------------------------------------- detección

  /** Puertos abiertos nuevos del escaneo frente al escaneo de puertos anterior (null = línea base). */
  private async newOpenPorts(assetId: string, scanId: string): Promise<PortInfo[] | null> {
    const current = await this.prisma.scan.findUnique({
      where: { id: scanId },
      select: {
        finishedAt: true,
        ports: {
          where: { state: 'open' },
          select: { port: true, protocol: true, serviceName: true, product: true, version: true },
        },
      },
    });
    if (!current) return null;
    const previous = await this.prisma.scan.findFirst({
      where: {
        assetId,
        type: ScanType.PORT_SCAN,
        status: ScanStatus.COMPLETED,
        id: { not: scanId },
        finishedAt: current.finishedAt ? { lte: current.finishedAt } : undefined,
      },
      orderBy: { finishedAt: 'desc' },
      select: { ports: { where: { state: 'open' }, select: { port: true, protocol: true, serviceName: true, product: true, version: true } } },
    });
    if (!previous) return null;
    return diffOpenPorts(previous.ports, current.ports);
  }

  /** Evalúa las reglas de alerta tras un escaneo completado. Nunca lanza: una alerta no debe romper un escaneo. */
  async handleScanCompleted(event: ScanCompletedEvent): Promise<number> {
    try {
      const asset = await this.prisma.asset.findFirst({
        where: { id: event.assetId, organizationId: event.organizationId },
        select: { id: true, value: true, name: true },
      });
      if (!asset) return 0;

      const newOpenPorts = event.scanType === ScanType.PORT_SCAN ? await this.newOpenPorts(asset.id, event.scanId) : null;
      const drafts = detectAlerts({
        asset,
        scan: { id: event.scanId, type: event.scanType },
        opened: event.opened,
        newOpenPorts,
        newHosts: event.newHosts,
      });
      if (drafts.length === 0) return 0;

      const created = await this.prisma.$transaction(
        drafts.map((d) =>
          this.prisma.alert.create({
            data: {
              organizationId: event.organizationId,
              assetId: asset.id,
              scanId: event.scanId,
              type: d.type,
              severity: d.severity,
              title: d.title.slice(0, 200),
              message: d.message,
              data: d.data as Prisma.InputJsonValue,
            },
            select: { id: true },
          }),
        ),
      );
      this.logger.log(`Escaneo ${event.scanId}: ${created.length} alerta(s) generada(s)`);
      this.track(this.deliver(created.map((a) => a.id)));
      return created.length;
    } catch (err) {
      this.logger.error(`No se pudieron evaluar las alertas del escaneo ${event.scanId}: ${(err as Error).message}`);
      return 0;
    }
  }

  // ------------------------------------------------------------------ entrega

  private async deliver(alertIds: string[]): Promise<void> {
    for (const id of alertIds) {
      const alert = await this.prisma.alert.findUnique({
        where: { id },
        select: {
          id: true,
          organizationId: true,
          type: true,
          severity: true,
          title: true,
          message: true,
          createdAt: true,
          asset: { select: { id: true, value: true, name: true } },
          organization: { select: { name: true } },
        },
      });
      if (!alert) continue;
      const channels = await this.prisma.alertChannel.findMany({
        where: { organizationId: alert.organizationId, isActive: true },
        select: { id: true, type: true, name: true, target: true, minSeverity: true },
        orderBy: { createdAt: 'asc' },
      });
      const eligible = channels.filter((c) => meetsThreshold(alert.severity, c.minSeverity));
      if (eligible.length === 0) continue;

      const msg: NotificationMessage = {
        kind: 'alert',
        alertId: alert.id,
        type: alert.type,
        severity: alert.severity,
        title: alert.title,
        message: alert.message,
        organizationName: alert.organization.name,
        asset: alert.asset,
        url: this.appUrl(alert.asset ? `/assets/${alert.asset.id}` : '/alerts'),
        createdAt: alert.createdAt,
      };
      const results: DeliveryResult[] = [];
      for (const channel of eligible) {
        const result = await this.notifier.send(channel, msg);
        results.push(result);
        await this.recordChannelDelivery(channel.id, result);
      }
      await this.prisma.alert.update({
        where: { id: alert.id },
        data: { deliveries: results as unknown as Prisma.InputJsonValue },
      });
    }
  }

  private async recordChannelDelivery(channelId: string, result: DeliveryResult): Promise<void> {
    await this.prisma.alertChannel.updateMany({
      where: { id: channelId },
      data: {
        lastDeliveryAt: new Date(result.at),
        lastDeliveryStatus: result.status,
        lastDeliveryError: result.error ? result.error.slice(0, 500) : null,
      },
    });
  }

  // ---------------------------------------------------------------- consultas

  async findAll(organizationId: string, query: ListAlertsQuery) {
    const where: Prisma.AlertWhereInput = {
      organizationId,
      type: query.type,
      severity: query.severity,
      assetId: query.assetId,
      acknowledgedAt: query.acknowledged === undefined ? undefined : query.acknowledged ? { not: null } : null,
    };
    const [items, total] = await this.prisma.$transaction([
      this.prisma.alert.findMany({
        where,
        select: alertSelect,
        orderBy: { createdAt: 'desc' },
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.alert.count({ where }),
    ]);
    return {
      items,
      meta: { total, page: query.page, pageSize: query.pageSize, totalPages: Math.max(1, Math.ceil(total / query.pageSize)) },
    };
  }

  async summary(organizationId: string) {
    const rows = await this.prisma.alert.groupBy({
      by: ['severity'],
      where: { organizationId, acknowledgedAt: null },
      _count: { id: true },
    });
    const bySeverity = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<FindingSeverity, number>;
    let unacknowledged = 0;
    for (const row of rows) {
      bySeverity[row.severity] = row._count.id;
      unacknowledged += row._count.id;
    }
    const latest = await this.prisma.alert.findFirst({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
      select: { createdAt: true },
    });
    return { unacknowledged, bySeverity, lastAlertAt: latest?.createdAt ?? null };
  }

  async acknowledge(actor: AuthUser, id: string) {
    const alert = await this.prisma.alert.findFirst({ where: { id, organizationId: actor.organizationId }, select: { id: true, acknowledgedAt: true } });
    if (!alert) throw new NotFoundException('Alerta no encontrada');
    if (alert.acknowledgedAt) {
      return this.prisma.alert.findUniqueOrThrow({ where: { id }, select: alertSelect });
    }
    return this.prisma.alert.update({
      where: { id },
      data: { acknowledgedAt: new Date(), acknowledgedById: actor.id },
      select: alertSelect,
    });
  }

  async acknowledgeAll(actor: AuthUser) {
    const { count } = await this.prisma.alert.updateMany({
      where: { organizationId: actor.organizationId, acknowledgedAt: null },
      data: { acknowledgedAt: new Date(), acknowledgedById: actor.id },
    });
    return { acknowledged: count };
  }

  // ------------------------------------------------------------------ canales

  private present(channel: ChannelRow) {
    return {
      ...channel,
      target: channel.type === AlertChannelType.WEBHOOK ? maskUrl(channel.target) : channel.target,
    };
  }

  /** Valida y normaliza el destino según el tipo de canal. */
  private normalizeTarget(type: AlertChannelType, target: string): string {
    if (type === AlertChannelType.EMAIL) {
      const recipients = [...new Set(parseRecipients(target))];
      if (recipients.length === 0) throw new BadRequestException('Indica al menos un destinatario de correo');
      if (recipients.length > MAX_RECIPIENTS) {
        throw new BadRequestException(`Máximo ${MAX_RECIPIENTS} destinatarios por canal`);
      }
      const invalid = recipients.find((r) => !isEmail(r));
      if (invalid) throw new BadRequestException(`Correo no válido: ${invalid}`);
      return recipients.join(', ');
    }
    const check = validateWebhookUrl(target, this.allowPrivate);
    if (!check.ok) throw new BadRequestException(check.reason);
    return check.url.toString();
  }

  async listChannels(organizationId: string) {
    const rows = await this.prisma.alertChannel.findMany({
      where: { organizationId },
      select: channelSelect,
      orderBy: { createdAt: 'asc' },
    });
    return { items: rows.map((c) => this.present(c)), emailEnabled: this.notifier.emailEnabled };
  }

  async createChannel(actor: AuthUser, dto: CreateAlertChannelDto) {
    const channel = await this.prisma.alertChannel.create({
      data: {
        organizationId: actor.organizationId,
        type: dto.type,
        name: dto.name,
        target: this.normalizeTarget(dto.type, dto.target),
        minSeverity: dto.minSeverity ?? FindingSeverity.HIGH,
        isActive: dto.isActive ?? true,
        createdById: actor.id,
      },
      select: channelSelect,
    });
    this.audit.record({
      organizationId: actor.organizationId,
      action: 'alert_channel.create',
      actor,
      target: { type: 'alert_channel', id: channel.id, label: channel.name },
      detail: { type: dto.type, minSeverity: channel.minSeverity },
    });
    return this.present(channel);
  }

  private async findChannel(organizationId: string, id: string) {
    const channel = await this.prisma.alertChannel.findFirst({
      where: { id, organizationId },
      select: { id: true, type: true, name: true, target: true },
    });
    if (!channel) throw new NotFoundException('Canal no encontrado');
    return channel;
  }

  async updateChannel(actor: AuthUser, id: string, dto: UpdateAlertChannelDto) {
    const organizationId = actor.organizationId;
    const existing = await this.findChannel(organizationId, id);
    const channel = await this.prisma.alertChannel.update({
      where: { id },
      data: {
        name: dto.name,
        target: dto.target === undefined ? undefined : this.normalizeTarget(existing.type, dto.target),
        minSeverity: dto.minSeverity,
        isActive: dto.isActive,
      },
      select: channelSelect,
    });
    this.audit.record({
      organizationId,
      action: 'alert_channel.update',
      actor,
      target: { type: 'alert_channel', id: channel.id, label: channel.name },
      detail: {
        ...(dto.name !== undefined ? { name: dto.name } : {}),
        ...(dto.target !== undefined ? { target: true } : {}),
        ...(dto.minSeverity !== undefined ? { minSeverity: dto.minSeverity } : {}),
        ...(dto.isActive !== undefined ? { isActive: dto.isActive } : {}),
      },
    });
    return this.present(channel);
  }

  async deleteChannel(actor: AuthUser, id: string) {
    const existing = await this.findChannel(actor.organizationId, id);
    await this.prisma.alertChannel.delete({ where: { id } });
    this.audit.record({
      organizationId: actor.organizationId,
      action: 'alert_channel.delete',
      actor,
      target: { type: 'alert_channel', id, label: existing.name },
    });
  }

  /** Envía una notificación de prueba por el canal y devuelve el resultado. */
  async testChannel(actor: AuthUser, id: string): Promise<DeliveryResult> {
    const channel = await this.findChannel(actor.organizationId, id);
    const org = await this.prisma.organization.findUniqueOrThrow({ where: { id: actor.organizationId }, select: { name: true } });
    const result = await this.notifier.send(channel, {
      kind: 'test',
      type: 'TEST',
      severity: FindingSeverity.INFO,
      title: 'Notificación de prueba de SSPM',
      message: `${actor.fullName} verificó el canal "${channel.name}". Si recibes este mensaje, las alertas de seguridad llegarán por aquí.`,
      organizationName: org.name,
      asset: null,
      url: this.appUrl('/alerts'),
      createdAt: new Date(),
    });
    await this.recordChannelDelivery(channel.id, result);
    return result;
  }
}
