import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AssetType, Prisma, ScanStatus, ScanType } from '@prisma/client';
import { AssetsService } from '../assets/assets.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { isPrivateOrReservedIp } from '../common/utils/network.util';
import { PrismaService } from '../prisma/prisma.service';
import { DiscoveredHostDraft } from '../scans/scanner.interface';

export interface SyncDiscoveryInput {
  organizationId: string;
  assetId: string;
  scanId: string;
  hosts: DiscoveredHostDraft[];
}

export interface SyncDiscoveryResult {
  /** Subdominios vistos por primera vez que no están en el inventario; null en el primer descubrimiento (línea base). */
  newHosts: string[] | null;
  summary: { total: number; new: number; baseline: boolean };
}

/**
 * Inventario de subdominios descubiertos (shadow IT): guarda lo que encuentra
 * el escáner SUBDOMAIN_DISCOVERY, permite ignorarlos o incorporarlos como
 * activos y señala los nuevos para las alertas.
 */
@Injectable()
export class DiscoveryService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly assets: AssetsService,
  ) {}

  /** Guarda los subdominios del escaneo (dentro de su transacción) en una única sentencia. */
  async syncForScan(tx: Prisma.TransactionClient, input: SyncDiscoveryInput): Promise<SyncDiscoveryResult> {
    const previous = await tx.scan.count({
      where: {
        assetId: input.assetId,
        type: ScanType.SUBDOMAIN_DISCOVERY,
        status: ScanStatus.COMPLETED,
        id: { not: input.scanId },
      },
    });
    const baseline = previous === 0;
    if (input.hosts.length === 0) {
      return { newHosts: baseline ? null : [], summary: { total: 0, new: 0, baseline } };
    }

    const h = input.hosts;
    const rows = await tx.$queryRaw<Array<{ hostname: string; inserted: boolean }>>`
      INSERT INTO discovered_hosts (
        id, organization_id, asset_id, hostname, source, resolves, addresses, wildcard,
        last_certificate_at, last_scan_id, first_seen_at, last_seen_at
      )
      SELECT gen_random_uuid(), ${input.organizationId}::uuid, ${input.assetId}::uuid, t.hostname, 'ct', t.resolves,
             CASE WHEN t.addresses = '' THEN ARRAY[]::text[] ELSE string_to_array(t.addresses, ',') END,
             t.wildcard, NULLIF(t.cert, '')::timestamptz, ${input.scanId}::uuid, now(), now()
        FROM unnest(
          ${h.map((x) => x.hostname)}::text[],
          ${h.map((x) => x.resolves)}::boolean[],
          ${h.map((x) => x.addresses.join(','))}::text[],
          ${h.map((x) => x.wildcard)}::boolean[],
          ${h.map((x) => x.lastCertificateAt?.toISOString() ?? '')}::text[]
        ) AS t(hostname, resolves, addresses, wildcard, cert)
      ON CONFLICT (organization_id, hostname) DO UPDATE SET
        resolves = EXCLUDED.resolves,
        addresses = EXCLUDED.addresses,
        wildcard = discovered_hosts.wildcard OR EXCLUDED.wildcard,
        last_certificate_at = GREATEST(discovered_hosts.last_certificate_at, EXCLUDED.last_certificate_at),
        last_scan_id = EXCLUDED.last_scan_id,
        last_seen_at = EXCLUDED.last_seen_at
      RETURNING hostname, (xmax = 0) AS inserted`;

    const inserted = rows.filter((r) => r.inserted).map((r) => r.hostname);
    if (baseline) {
      return { newHosts: null, summary: { total: rows.length, new: inserted.length, baseline } };
    }
    const inInventory = new Set(
      (
        await tx.asset.findMany({
          where: { organizationId: input.organizationId, value: { in: inserted } },
          select: { value: true },
        })
      ).map((a) => a.value),
    );
    const newHosts = inserted.filter((name) => !inInventory.has(name)).sort();
    return { newHosts, summary: { total: rows.length, new: inserted.length, baseline } };
  }

  async listForAsset(organizationId: string, assetId: string) {
    const asset = await this.prisma.asset.findFirst({
      where: { id: assetId, organizationId },
      select: { id: true, type: true, value: true },
    });
    if (!asset) throw new NotFoundException('Activo no encontrado');

    const [hosts, lastScan] = await Promise.all([
      this.prisma.discoveredHost.findMany({
        where: { organizationId, assetId },
        orderBy: [{ hostname: 'asc' }],
      }),
      this.prisma.scan.findFirst({
        where: { assetId, type: ScanType.SUBDOMAIN_DISCOVERY, status: ScanStatus.COMPLETED },
        orderBy: { finishedAt: 'desc' },
        select: { id: true, finishedAt: true, summary: true },
      }),
    ]);
    const inventory = new Map(
      (
        await this.prisma.asset.findMany({
          where: { organizationId, value: { in: hosts.map((h) => h.hostname) } },
          select: { id: true, value: true },
        })
      ).map((a) => [a.value, a.id]),
    );

    const items = hosts.map((h) => ({
      id: h.id,
      hostname: h.hostname,
      resolves: h.resolves,
      addresses: h.addresses,
      /** Resuelve a una IP interna: el nombre revela infraestructura privada. */
      internal: h.addresses.some((a) => isPrivateOrReservedIp(a)),
      wildcard: h.wildcard,
      lastCertificateAt: h.lastCertificateAt,
      firstSeenAt: h.firstSeenAt,
      lastSeenAt: h.lastSeenAt,
      ignored: h.ignoredAt !== null,
      inventoryAssetId: inventory.get(h.hostname) ?? null,
    }));
    return {
      asset,
      lastDiscovery: lastScan ? { scanId: lastScan.id, finishedAt: lastScan.finishedAt, summary: lastScan.summary } : null,
      summary: {
        total: items.length,
        resolving: items.filter((i) => i.resolves).length,
        pending: items.filter((i) => !i.ignored && !i.inventoryAssetId).length,
        ignored: items.filter((i) => i.ignored).length,
        inInventory: items.filter((i) => i.inventoryAssetId).length,
      },
      items,
    };
  }

  async setIgnored(organizationId: string, id: string, ignored: boolean) {
    const host = await this.prisma.discoveredHost.findFirst({ where: { id, organizationId }, select: { id: true } });
    if (!host) throw new NotFoundException('Subdominio no encontrado');
    const updated = await this.prisma.discoveredHost.update({
      where: { id },
      data: { ignoredAt: ignored ? new Date() : null },
      select: { id: true, hostname: true, ignoredAt: true },
    });
    return { id: updated.id, hostname: updated.hostname, ignored: updated.ignoredAt !== null };
  }

  /**
   * Incorpora subdominios descubiertos al inventario. Los que cuelgan de un
   * dominio verificado por DNS heredan la verificación y se pueden auditar ya.
   */
  async importAsAssets(actor: AuthUser, ids: string[]) {
    const hosts = await this.prisma.discoveredHost.findMany({
      where: { id: { in: ids }, organizationId: actor.organizationId },
      select: { id: true, hostname: true },
    });
    if (hosts.length !== new Set(ids).size) throw new NotFoundException('Algún subdominio no existe en tu organización');

    const created: Array<{ hostname: string; assetId: string; verified: boolean }> = [];
    const failed: Array<{ hostname: string; reason: string }> = [];
    for (const host of hosts) {
      try {
        const asset = await this.assets.create(actor, {
          value: host.hostname,
          type: AssetType.DOMAIN,
          authorizationConfirmed: true,
        });
        created.push({ hostname: host.hostname, assetId: asset.id, verified: asset.verifiedAt !== null });
      } catch (err) {
        const reason =
          err instanceof ConflictException || (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002')
            ? 'Ya está en el inventario'
            : err instanceof BadRequestException
              ? err.message
              : 'No se pudo registrar';
        failed.push({ hostname: host.hostname, reason });
      }
    }
    return { created, failed };
  }
}
