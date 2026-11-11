import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';

export interface GcpAuthInput {
  projectId: string;
  clientEmail?: string;
  privateKey?: string;
  serviceAccountJson?: string;
}

export interface GcpVerificationResult {
  valid: boolean;
  projectId?: string;
  projectNumber?: string;
  displayName?: string;
  clientEmail?: string;
  state?: string;
  latencyMs: number;
  error?: string;
}

function base64url(input: string | Buffer): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

@Injectable()
export class GcpConnectorService {
  private readonly logger = new Logger(GcpConnectorService.name);

  /**
   * Extrae y valida las credenciales de Service Account de GCP, ya sea
   * desde campos individuales o desde el contenido JSON del archivo de clave.
   */
  parseCredentials(input: GcpAuthInput): {
    projectId: string;
    clientEmail: string;
    privateKey: string;
  } {
    let projectId = input.projectId?.trim();
    let clientEmail = input.clientEmail?.trim();
    let privateKey = input.privateKey?.trim();

    if (input.serviceAccountJson?.trim()) {
      try {
        const parsed = JSON.parse(input.serviceAccountJson.trim());
        if (parsed.project_id) projectId = String(parsed.project_id).trim();
        if (parsed.client_email) clientEmail = String(parsed.client_email).trim();
        if (parsed.private_key) privateKey = String(parsed.private_key).trim();
      } catch {
        throw new BadRequestException('El formato del JSON de la Service Account de GCP no es válido.');
      }
    }

    if (!projectId) {
      throw new BadRequestException('Se requiere el Project ID de Google Cloud Platform.');
    }
    if (!clientEmail) {
      throw new BadRequestException('Se requiere el Client Email de la Service Account de GCP.');
    }
    if (!privateKey) {
      throw new BadRequestException('Se requiere la Private Key (PEM) de la Service Account de GCP.');
    }

    // Normalizar saltos de línea en la clave privada si viene con escapes literales \n
    if (privateKey.includes('\\n')) {
      privateKey = privateKey.replace(/\\n/g, '\n');
    }

    return { projectId, clientEmail, privateKey };
  }

  /**
   * Genera un JWT firmado con RS256 (RFC 7523) para intercambio de tokens con Google OAuth2.
   */
  createSignedJwt(
    clientEmail: string,
    privateKey: string,
    scopes: string[] = ['https://www.googleapis.com/auth/cloud-platform.read-only'],
  ): string {
    const now = Math.floor(Date.now() / 1000);
    const header = {
      alg: 'RS256',
      typ: 'JWT',
    };
    const claims = {
      iss: clientEmail,
      scope: scopes.join(' '),
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600,
      iat: now,
    };

    const encodedHeader = base64url(JSON.stringify(header));
    const encodedClaims = base64url(JSON.stringify(claims));
    const payloadToSign = `${encodedHeader}.${encodedClaims}`;

    const signer = crypto.createSign('RSA-SHA256');
    signer.update(payloadToSign);
    signer.end();

    const signature = signer.sign(privateKey);
    const encodedSignature = base64url(signature);

    return `${payloadToSign}.${encodedSignature}`;
  }

  /**
   * Obtiene un token de acceso OAuth2 para la Service Account de GCP.
   */
  async acquireAccessToken(input: GcpAuthInput): Promise<{
    accessToken: string;
    expiresIn: number;
    projectId: string;
    clientEmail: string;
  }> {
    const creds = this.parseCredentials(input);
    const signedJwt = this.createSignedJwt(creds.clientEmail, creds.privateKey);

    const form = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: signedJwt,
    });

    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: form.toString(),
      signal: AbortSignal.timeout(15000),
    });

    const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;

    if (!response.ok || !data.access_token) {
      const errorMsg =
        typeof data.error_description === 'string'
          ? data.error_description
          : typeof data.error === 'string'
            ? data.error
            : `Google OAuth2 rechazó la autenticación (HTTP ${response.status})`;
      throw new Error(errorMsg);
    }

    return {
      accessToken: String(data.access_token),
      expiresIn: Number(data.expires_in ?? 3599),
      projectId: creds.projectId,
      clientEmail: creds.clientEmail,
    };
  }

  /**
   * Verifica la conectividad real con Google Cloud Platform:
   * 1. Autentica la Service Account y genera el token de acceso.
   * 2. Consulta los metadatos del proyecto en Cloud Resource Manager v1.
   */
  async verifyConnection(input: GcpAuthInput): Promise<GcpVerificationResult> {
    const start = Date.now();
    try {
      const creds = this.parseCredentials(input);
      const { accessToken } = await this.acquireAccessToken(input);

      const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(creds.projectId)}`;
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
        signal: AbortSignal.timeout(15000),
      });

      const latencyMs = Date.now() - start;
      const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;

      if (!response.ok) {
        const errObj = (data.error && typeof data.error === 'object' ? data.error : {}) as Record<string, unknown>;
        const msg =
          typeof errObj.message === 'string'
            ? errObj.message
            : `Fallo al consultar Cloud Resource Manager (HTTP ${response.status}). Verifique los roles Viewer o Security Reviewer.`;
        return {
          valid: false,
          projectId: creds.projectId,
          clientEmail: creds.clientEmail,
          latencyMs,
          error: msg,
        };
      }

      return {
        valid: true,
        projectId: String(data.projectId ?? creds.projectId),
        projectNumber: String(data.projectNumber ?? ''),
        displayName: String(data.name ?? creds.projectId),
        clientEmail: creds.clientEmail,
        state: String(data.lifecycleState ?? 'ACTIVE'),
        latencyMs,
      };
    } catch (err) {
      const latencyMs = Date.now() - start;
      const message = err instanceof Error ? err.message : 'Error desconocido al conectar con Google Cloud Platform';
      this.logger.warn(`Fallo de verificación GCP para proyecto ${input.projectId}: ${message}`);
      return {
        valid: false,
        projectId: input.projectId,
        latencyMs,
        error: message,
      };
    }
  }

  /**
   * Ejecuta una petición GET autenticada contra las APIs REST de Google Cloud.
   */
  async executeGcpGet<T = unknown>(
    accessToken: string,
    url: string,
  ): Promise<{ ok: boolean; status: number; data: T }> {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(15000),
    });

    const data = (await response.json().catch(() => ({}))) as T;
    return {
      ok: response.ok,
      status: response.status,
      data,
    };
  }
}
