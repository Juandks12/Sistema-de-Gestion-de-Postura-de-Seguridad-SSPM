import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CloudAuthType } from '@prisma/client';
import { XMLParser } from 'fast-xml-parser';
import { AwsCredentials, signAwsRequest } from './aws-sigv4.util';

export interface AwsAuthInput {
  authType: CloudAuthType;
  accountId: string;
  roleArn?: string | null;
  externalId?: string | null;
  accessKeyId?: string | null;
  secretAccessKey?: string | null;
  sessionToken?: string | null;
}

export interface AwsVerificationResult {
  valid: boolean;
  accountId?: string;
  arn?: string;
  userId?: string;
  assumedRole?: boolean;
  latencyMs: number;
  error?: string;
}

@Injectable()
export class AwsConnectorService {
  private readonly logger = new Logger(AwsConnectorService.name);
  private readonly xmlParser = new XMLParser({
    ignoreAttributes: false,
    parseTagValue: false,
    trimValues: true,
  });

  constructor(private readonly config: ConfigService) {}

  /**
   * Resuelve credenciales operativas de AWS:
   * - Si authType es ACCESS_KEYS, retorna directamente el par AccessKeyId/SecretAccessKey.
   * - Si authType es ROLE_ARN, invoca sts:AssumeRole con ExternalId para obtener credenciales temporales.
   */
  async resolveCredentials(input: AwsAuthInput): Promise<{ credentials: AwsCredentials; assumedRole: boolean }> {
    if (input.authType === CloudAuthType.ACCESS_KEYS) {
      if (!input.accessKeyId || !input.secretAccessKey) {
        throw new BadRequestException('Se requieren Access Key ID y Secret Access Key para autenticar en AWS.');
      }
      return {
        credentials: {
          accessKeyId: input.accessKeyId.trim(),
          secretAccessKey: input.secretAccessKey.trim(),
          sessionToken: input.sessionToken?.trim() || undefined,
        },
        assumedRole: false,
      };
    }

    if (input.authType === CloudAuthType.ROLE_ARN) {
      if (!input.roleArn) {
        throw new BadRequestException('Se requiere el ARN del rol IAM (awsRoleArn) para ejecutar AssumeRole.');
      }

      const baseAccessKey = input.accessKeyId?.trim() || this.config.get<string>('AWS_SCANNER_ACCESS_KEY_ID');
      const baseSecretKey = input.secretAccessKey?.trim() || this.config.get<string>('AWS_SCANNER_SECRET_ACCESS_KEY');

      if (!baseAccessKey || !baseSecretKey) {
        throw new BadRequestException(
          'Para asumir un rol Cross-Account (AssumeRole) se requieren credenciales base del escáner ' +
          '(AWS_SCANNER_ACCESS_KEY_ID / AWS_SCANNER_SECRET_ACCESS_KEY) o credenciales de salto.',
        );
      }

      const baseCreds: AwsCredentials = {
        accessKeyId: baseAccessKey,
        secretAccessKey: baseSecretKey,
      };

      const formParams = new URLSearchParams({
        Action: 'AssumeRole',
        Version: '2011-06-15',
        RoleArn: input.roleArn.trim(),
        RoleSessionName: 'sspm-cspm-auditor-session',
        DurationSeconds: '3600',
      });

      if (input.externalId?.trim()) {
        formParams.set('ExternalId', input.externalId.trim());
      }

      const signed = signAwsRequest({
        method: 'POST',
        url: 'https://sts.amazonaws.com/',
        region: 'us-east-1',
        service: 'sts',
        credentials: baseCreds,
        headers: {
          'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
        },
        body: formParams.toString(),
      });

      const response = await fetch(signed.url, {
        method: signed.method,
        headers: signed.headers,
        body: signed.body,
        signal: AbortSignal.timeout(15000),
      });

      const xmlText = await response.text();
      const parsed = this.xmlParser.parse(xmlText);

      if (!response.ok) {
        const errMsg =
          parsed?.ErrorResponse?.Error?.Message ||
          parsed?.Error?.Message ||
          `AWS STS AssumeRole falló con HTTP ${response.status}`;
        throw new Error(`No se pudo asumir el rol IAM (${input.roleArn}): ${errMsg}`);
      }

      const credsNode = parsed?.AssumeRoleResponse?.AssumeRoleResult?.Credentials;
      if (!credsNode?.AccessKeyId || !credsNode?.SecretAccessKey) {
        throw new Error('Respuesta de AWS STS AssumeRole incompleta o sin credenciales temporales.');
      }

      return {
        credentials: {
          accessKeyId: String(credsNode.AccessKeyId),
          secretAccessKey: String(credsNode.SecretAccessKey),
          sessionToken: credsNode.SessionToken ? String(credsNode.SessionToken) : undefined,
        },
        assumedRole: true,
      };
    }

    throw new BadRequestException(`Tipo de autenticación no soportado para AWS: ${input.authType}`);
  }

  /**
   * Verifica la conectividad real contra AWS STS (GetCallerIdentity) y comprueba que el
   * Account ID coincida con el registrado por la organización.
   */
  async verifyConnection(input: AwsAuthInput): Promise<AwsVerificationResult> {
    const start = Date.now();
    try {
      const { credentials, assumedRole } = await this.resolveCredentials(input);

      const body = new URLSearchParams({
        Action: 'GetCallerIdentity',
        Version: '2011-06-15',
      }).toString();

      const signed = signAwsRequest({
        method: 'POST',
        url: 'https://sts.amazonaws.com/',
        region: 'us-east-1',
        service: 'sts',
        credentials,
        headers: {
          'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
        },
        body,
      });

      const response = await fetch(signed.url, {
        method: signed.method,
        headers: signed.headers,
        body: signed.body,
        signal: AbortSignal.timeout(15000),
      });

      const latencyMs = Date.now() - start;
      const xmlText = await response.text();
      const parsed = this.xmlParser.parse(xmlText);

      if (!response.ok) {
        const errMsg =
          parsed?.ErrorResponse?.Error?.Message ||
          parsed?.Error?.Message ||
          `Error HTTP ${response.status} al consultar AWS STS GetCallerIdentity`;
        return {
          valid: false,
          latencyMs,
          error: errMsg,
        };
      }

      const resultNode = parsed?.GetCallerIdentityResponse?.GetCallerIdentityResult;
      const returnedAccount = resultNode?.Account ? String(resultNode.Account).trim() : '';
      const returnedArn = resultNode?.Arn ? String(resultNode.Arn).trim() : '';
      const returnedUserId = resultNode?.UserId ? String(resultNode.UserId).trim() : '';

      if (!returnedAccount) {
        return {
          valid: false,
          latencyMs,
          error: 'AWS STS no devolvió un identificador de cuenta válido.',
        };
      }

      const expectedAccount = input.accountId?.replace(/\D/g, '');
      if (expectedAccount && returnedAccount !== expectedAccount) {
        return {
          valid: false,
          accountId: returnedAccount,
          arn: returnedArn,
          userId: returnedUserId,
          assumedRole,
          latencyMs,
          error: `Las credenciales pertenecen a la cuenta AWS ${returnedAccount}, pero se esperaba ${expectedAccount}.`,
        };
      }

      return {
        valid: true,
        accountId: returnedAccount,
        arn: returnedArn,
        userId: returnedUserId,
        assumedRole,
        latencyMs,
      };
    } catch (err) {
      const latencyMs = Date.now() - start;
      const message = err instanceof Error ? err.message : 'Error desconocido al conectar con AWS STS';
      this.logger.warn(`Fallo de verificación AWS para cuenta ${input.accountId}: ${message}`);
      return {
        valid: false,
        latencyMs,
        error: message,
      };
    }
  }

  /**
   * Ejecuta una llamada firmada SigV4 contra una API Query/XML o REST de AWS.
   */
  async executeSignedXmlRequest(params: {
    method: 'GET' | 'POST';
    url: string;
    region: string;
    service: string;
    credentials: AwsCredentials;
    headers?: Record<string, string>;
    body?: string;
  }): Promise<{ ok: boolean; status: number; data: any; rawText: string }> {
    const signed = signAwsRequest(params);
    const response = await fetch(signed.url, {
      method: signed.method,
      headers: signed.headers,
      body: signed.body,
      signal: AbortSignal.timeout(15000),
    });

    const rawText = await response.text();
    let data: any = null;
    if (rawText) {
      try {
        data = rawText.trim().startsWith('{') ? JSON.parse(rawText) : this.xmlParser.parse(rawText);
      } catch {
        data = rawText;
      }
    }

    return {
      ok: response.ok,
      status: response.status,
      data,
      rawText,
    };
  }
}
