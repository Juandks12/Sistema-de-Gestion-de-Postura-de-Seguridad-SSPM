import { BadRequestException, Injectable, Logger } from '@nestjs/common';

export interface AzureAuthInput {
  subscriptionId: string;
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export interface AzureVerificationResult {
  valid: boolean;
  subscriptionId?: string;
  displayName?: string;
  state?: string;
  tenantId?: string;
  latencyMs: number;
  error?: string;
}

@Injectable()
export class AzureConnectorService {
  private readonly logger = new Logger(AzureConnectorService.name);

  /**
   * Obtiene un token OAuth2 de Microsoft Entra ID (Azure AD) mediante Client Credentials
   * con alcance hacia Azure Resource Manager (https://management.azure.com/.default).
   */
  async acquireManagementToken(input: {
    tenantId: string;
    clientId: string;
    clientSecret: string;
  }): Promise<{ accessToken: string; expiresIn: number }> {
    const tenantId = input.tenantId?.trim();
    const clientId = input.clientId?.trim();
    const clientSecret = input.clientSecret?.trim();

    if (!tenantId || !clientId || !clientSecret) {
      throw new BadRequestException(
        'Se requieren Tenant ID, Client ID y Client Secret para autenticar contra Microsoft Entra ID.',
      );
    }

    const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
    const form = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret,
      scope: 'https://management.azure.com/.default',
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: form.toString(),
      signal: AbortSignal.timeout(15000),
    });

    const data = (await response.json().catch(() => ({}))) as Record<string, any>;

    if (!response.ok || !data.access_token) {
      const errorDetail =
        data.error_description ||
        data.error ||
        `Microsoft Entra ID rechazó la solicitud de token (HTTP ${response.status})`;
      throw new Error(String(errorDetail).split('\r\n')[0]);
    }

    return {
      accessToken: String(data.access_token),
      expiresIn: Number(data.expires_in ?? 3599),
    };
  }

  /**
   * Verifica la conectividad real con Azure:
   * 1. Autentica el Service Principal en Microsoft Entra ID.
   * 2. Consulta los metadatos de la suscripción en Azure Resource Manager (ARM).
   */
  async verifyConnection(input: AzureAuthInput): Promise<AzureVerificationResult> {
    const start = Date.now();
    try {
      const subscriptionId = input.subscriptionId?.trim();
      if (!subscriptionId) {
        throw new BadRequestException('Se requiere el Subscription ID de Azure.');
      }

      const { accessToken } = await this.acquireManagementToken({
        tenantId: input.tenantId,
        clientId: input.clientId,
        clientSecret: input.clientSecret,
      });

      const subUrl = `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}?api-version=2022-12-01`;
      const response = await fetch(subUrl, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
        },
        signal: AbortSignal.timeout(15000),
      });

      const latencyMs = Date.now() - start;
      const body = (await response.json().catch(() => ({}))) as Record<string, any>;

      if (!response.ok) {
        const armMsg =
          body?.error?.message ||
          `Autenticación exitosa en Entra ID, pero ARM devolvió HTTP ${response.status}. Verifique que el rol Reader esté asignado en la suscripción ${subscriptionId}.`;
        return {
          valid: false,
          subscriptionId,
          tenantId: input.tenantId.trim(),
          latencyMs,
          error: armMsg,
        };
      }

      return {
        valid: true,
        subscriptionId: String(body.subscriptionId ?? subscriptionId),
        displayName: String(body.displayName ?? subscriptionId),
        state: String(body.state ?? 'Enabled'),
        tenantId: input.tenantId.trim(),
        latencyMs,
      };
    } catch (err) {
      const latencyMs = Date.now() - start;
      const message = err instanceof Error ? err.message : 'Error desconocido al conectar con Azure ARM';
      this.logger.warn(`Fallo de verificación Azure para suscripción ${input.subscriptionId}: ${message}`);
      return {
        valid: false,
        latencyMs,
        error: message,
      };
    }
  }

  /**
   * Ejecuta una consulta GET autenticada contra Azure Resource Manager (ARM).
   */
  async executeArmGet<T = any>(
    accessToken: string,
    armPathOrUrl: string,
  ): Promise<{ ok: boolean; status: number; data: T }> {
    const url = armPathOrUrl.startsWith('https://')
      ? armPathOrUrl
      : `https://management.azure.com${armPathOrUrl.startsWith('/') ? '' : '/'}${armPathOrUrl}`;

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
