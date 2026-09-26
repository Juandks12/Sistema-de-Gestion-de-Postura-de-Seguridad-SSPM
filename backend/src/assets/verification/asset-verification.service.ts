import { BadRequestException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AssetType, Prisma, VerificationMethod } from '@prisma/client';
import { resolveTxt as dnsResolveTxt } from 'node:dns/promises';
import { isIP } from 'node:net';
import { PrismaService } from '../../prisma/prisma.service';
import { httpProbe } from '../../scans/web/http-client';
import {
  dnsProofDomains,
  dnsRecordName,
  expectedProof,
  fileContentMatches,
  isCoveredBy,
  txtRecordsContain,
  VERIFICATION_FILE_PATH,
} from './ownership';

/** Resuelve registros TXT. Se inyecta para poder sustituirlo en las pruebas. */
export type TxtResolver = (name: string) => Promise<string[][]>;
export const TXT_RESOLVER = Symbol('TXT_RESOLVER');
export const defaultTxtResolver: TxtResolver = (name) => dnsResolveTxt(name);

export type RequestedMethod = 'DNS_TXT' | 'HTTP_FILE';

export interface VerificationAttempt {
  method: RequestedMethod;
  target: string;
  ok: boolean;
  detail: string;
}

type Db = Prisma.TransactionClient | PrismaService;

const DNS_NOT_FOUND = new Set(['ENOTFOUND', 'ENODATA', 'ENONAME', 'NXDOMAIN']);

function portList(raw: string | undefined, fallback: number): number[] {
  const ports = (raw ?? '')
    .split(',')
    .map((p) => Number(p.trim()))
    .filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
  return ports.length > 0 ? [...new Set(ports)] : [fallback];
}

function hostForUrl(value: string): string {
  return isIP(value) === 6 ? `[${value}]` : value;
}

/**
 * Verificación de propiedad de activos (sección 1.6.3): sin ella no se
 * permite escanear un activo, para que la plataforma no pueda usarse contra
 * sistemas de terceros.
 */
@Injectable()
export class AssetVerificationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    @Inject(TXT_RESOLVER) private readonly resolveTxt: TxtResolver,
  ) {}

  get required(): boolean {
    return this.config.get<boolean>('ASSET_VERIFICATION_REQUIRED') !== false;
  }

  private get allowPrivate(): boolean {
    return this.config.get<boolean>('ALLOW_PRIVATE_TARGETS') === true;
  }

  /** URLs donde se busca el archivo de verificación, primero HTTPS. */
  fileUrls(value: string): string[] {
    const host = hostForUrl(value);
    const https = portList(this.config.get<string>('WEB_HTTPS_PORTS'), 443).map(
      (p) => `https://${host}${p === 443 ? '' : `:${p}`}${VERIFICATION_FILE_PATH}`,
    );
    const http = portList(this.config.get<string>('WEB_HTTP_PORTS'), 80).map(
      (p) => `http://${host}${p === 80 ? '' : `:${p}`}${VERIFICATION_FILE_PATH}`,
    );
    return [...https, ...http];
  }

  /**
   * Hereda la verificación de un dominio padre ya verificado por DNS en la
   * organización (un TXT en example.com cubre www.example.com).
   */
  async inheritedVerification(db: Db, organizationId: string, type: AssetType, value: string) {
    if (type !== AssetType.DOMAIN) return null;
    const verified = await db.asset.findMany({
      where: {
        organizationId,
        verifiedAt: { not: null },
        verificationMethod: { in: [VerificationMethod.DNS_TXT, VerificationMethod.INHERITED] },
        verificationScope: { not: null },
      },
      select: { verificationScope: true },
    });
    const scope = verified.map((a) => a.verificationScope!).find((s) => isCoveredBy(value, s));
    return scope ? { verifiedAt: new Date(), verificationMethod: VerificationMethod.INHERITED, verificationScope: scope } : null;
  }

  private async loadAsset(organizationId: string, assetId: string) {
    const asset = await this.prisma.asset.findFirst({
      where: { id: assetId, organizationId },
      select: {
        id: true,
        type: true,
        value: true,
        verifiedAt: true,
        verificationMethod: true,
        verificationScope: true,
        verificationCheckedAt: true,
        verificationError: true,
        organization: { select: { verificationToken: true } },
      },
    });
    if (!asset) throw new NotFoundException('Activo no encontrado');
    return asset;
  }

  /** Estado de verificación del activo e instrucciones para verificarlo. */
  async status(organizationId: string, assetId: string) {
    const asset = await this.loadAsset(organizationId, assetId);
    const proof = expectedProof(asset.organization.verificationToken);
    return {
      assetId: asset.id,
      type: asset.type,
      value: asset.value,
      required: this.required,
      verified: asset.verifiedAt !== null,
      verifiedAt: asset.verifiedAt,
      method: asset.verificationMethod,
      scope: asset.verificationScope,
      checkedAt: asset.verificationCheckedAt,
      error: asset.verificationError,
      proof,
      dns:
        asset.type === AssetType.DOMAIN
          ? {
              type: 'TXT',
              value: proof,
              recordName: dnsRecordName(asset.value),
              /** Nombres alternativos: un registro en un dominio superior cubre todos sus subdominios. */
              alternatives: dnsProofDomains(asset.value).slice(1).map(dnsRecordName),
            }
          : null,
      file: { content: proof, urls: this.fileUrls(asset.value) },
    };
  }

  private async checkDns(value: string, proof: string, attempts: VerificationAttempt[]): Promise<string | null> {
    for (const domain of dnsProofDomains(value)) {
      const name = dnsRecordName(domain);
      try {
        const records = await this.resolveTxt(name);
        if (txtRecordsContain(records, proof)) {
          attempts.push({ method: 'DNS_TXT', target: name, ok: true, detail: 'Registro TXT encontrado' });
          return domain;
        }
        attempts.push({ method: 'DNS_TXT', target: name, ok: false, detail: 'Hay registros TXT, pero ninguno contiene el valor esperado' });
      } catch (err) {
        const code = (err as { code?: string }).code ?? '';
        attempts.push({
          method: 'DNS_TXT',
          target: name,
          ok: false,
          detail: DNS_NOT_FOUND.has(code) ? 'No existe el registro TXT' : `Error de DNS (${code || 'desconocido'})`,
        });
      }
    }
    return null;
  }

  private async checkFile(value: string, proof: string, attempts: VerificationAttempt[]): Promise<boolean> {
    const timeoutMs = this.config.get<number>('WEB_REQUEST_TIMEOUT_MS') ?? 10000;
    for (const url of this.fileUrls(value)) {
      // Sin redirecciones: una redirección abierta del sitio no debe permitir
      // "demostrar" la propiedad con un archivo alojado en otro dominio.
      const res = await httpProbe(url, {
        allowPrivate: this.allowPrivate,
        signal: AbortSignal.timeout(timeoutMs + 1000),
        timeoutMs,
        maxRedirects: 0,
        maxBodyBytes: 4096,
      });
      if (!res.ok) {
        attempts.push({ method: 'HTTP_FILE', target: url, ok: false, detail: res.error });
        continue;
      }
      if (res.status !== 200) {
        attempts.push({
          method: 'HTTP_FILE',
          target: url,
          ok: false,
          detail: res.status >= 300 && res.status < 400 ? `Redirección HTTP ${res.status} (no se siguen redirecciones)` : `HTTP ${res.status}`,
        });
        continue;
      }
      if (fileContentMatches(res.body.toString('utf8'), proof)) {
        attempts.push({ method: 'HTTP_FILE', target: url, ok: true, detail: 'Archivo encontrado con el contenido esperado' });
        return true;
      }
      attempts.push({ method: 'HTTP_FILE', target: url, ok: false, detail: 'El archivo existe pero su contenido no coincide' });
    }
    return false;
  }

  /**
   * Comprueba la prueba publicada. Por defecto intenta DNS y después el
   * archivo (las IP solo admiten archivo). Un fallo no retira una
   * verificación anterior: queda registrado para que el usuario lo vea.
   */
  async verify(organizationId: string, assetId: string, method?: RequestedMethod) {
    const asset = await this.loadAsset(organizationId, assetId);
    if (asset.type === AssetType.IP && method === 'DNS_TXT') {
      throw new BadRequestException('Las direcciones IP solo pueden verificarse con el archivo HTTP');
    }
    const proof = expectedProof(asset.organization.verificationToken);
    const attempts: VerificationAttempt[] = [];
    const now = new Date();

    let success: { method: VerificationMethod; scope: string } | null = null;
    if (asset.type === AssetType.DOMAIN && method !== 'HTTP_FILE') {
      const scope = await this.checkDns(asset.value, proof, attempts);
      if (scope) success = { method: VerificationMethod.DNS_TXT, scope };
    }
    if (!success && method !== 'DNS_TXT' && (await this.checkFile(asset.value, proof, attempts))) {
      success = { method: VerificationMethod.HTTP_FILE, scope: asset.value };
    }

    if (success) {
      await this.prisma.$transaction(async (tx) => {
        await tx.asset.update({
          where: { id: asset.id },
          data: {
            verifiedAt: now,
            verificationMethod: success.method,
            verificationScope: success.scope,
            verificationCheckedAt: now,
            verificationError: null,
          },
        });
        if (success.method === VerificationMethod.DNS_TXT) {
          await this.propagate(tx, organizationId, success.scope, now);
        }
      });
    } else {
      const summary = attempts
        .map((a) => `${a.target}: ${a.detail}`)
        .join('; ')
        .slice(0, 500);
      await this.prisma.asset.update({
        where: { id: asset.id },
        data: { verificationCheckedAt: now, verificationError: summary || 'No se encontró la prueba de verificación' },
      });
    }

    return { ...(await this.status(organizationId, assetId)), attempts, success: success !== null };
  }

  /** Marca como verificados los demás dominios de la organización cubiertos por la prueba DNS. */
  private async propagate(tx: Prisma.TransactionClient, organizationId: string, scope: string, now: Date) {
    const candidates = await tx.asset.findMany({
      where: { organizationId, type: AssetType.DOMAIN, verifiedAt: null },
      select: { id: true, value: true },
    });
    const covered = candidates.filter((a) => isCoveredBy(a.value, scope)).map((a) => a.id);
    if (covered.length === 0) return;
    await tx.asset.updateMany({
      where: { id: { in: covered } },
      data: {
        verifiedAt: now,
        verificationMethod: VerificationMethod.INHERITED,
        verificationScope: scope,
        verificationCheckedAt: now,
        verificationError: null,
      },
    });
  }
}
