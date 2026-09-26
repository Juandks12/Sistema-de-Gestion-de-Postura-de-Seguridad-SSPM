import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { createHash } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { AuthResponse, AuthService } from './auth.service';
import { LoginProtectionService } from './login-protection.service';
import { generateRecoveryCode, generateTotpSecret, normalizeRecoveryCode, otpauthUrl, verifyTotp } from './totp';

const RECOVERY_CODES = 10;

export function recoveryCodeHash(code: string): string {
  return createHash('sha256').update(normalizeRecoveryCode(code)).digest('hex');
}

interface MfaTokenPayload {
  sub: string;
  purpose: 'mfa';
  ver: number;
}

/**
 * Verificación en dos pasos (TOTP, RFC 6238) opcional por usuario, compatible
 * con cualquier aplicación de autenticación. Incluye códigos de recuperación
 * de un solo uso por si se pierde el dispositivo.
 */
@Injectable()
export class MfaService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly auth: AuthService,
    private readonly audit: AuditService,
    private readonly loginProtection: LoginProtectionService,
  ) {}

  /** Estado del MFA del propio usuario. */
  async status(actor: AuthUser) {
    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: actor.id },
      select: { mfaEnabled: true, mfaEnabledAt: true, mfaRecoveryCodes: true },
    });
    return {
      enabled: user.mfaEnabled,
      enabledAt: user.mfaEnabledAt,
      recoveryCodesLeft: user.mfaEnabled ? user.mfaRecoveryCodes.length : 0,
    };
  }

  /** Genera un secreto nuevo y lo deja pendiente hasta confirmar el primer código. */
  async setup(actor: AuthUser) {
    const user = await this.prisma.user.findUniqueOrThrow({ where: { id: actor.id } });
    if (user.mfaEnabled) {
      throw new BadRequestException('La verificación en dos pasos ya está activada');
    }
    const secret = generateTotpSecret();
    await this.prisma.user.update({ where: { id: actor.id }, data: { mfaPendingSecret: secret } });
    return {
      secret,
      otpauthUrl: otpauthUrl('SSPM', actor.email, secret),
      digits: 6,
      periodSeconds: 30,
    };
  }

  /** Confirma el primer código y activa el MFA. Devuelve los códigos de recuperación una sola vez. */
  async enable(actor: AuthUser, code: string) {
    const user = await this.prisma.user.findUniqueOrThrow({ where: { id: actor.id } });
    if (user.mfaEnabled) {
      throw new BadRequestException('La verificación en dos pasos ya está activada');
    }
    if (!user.mfaPendingSecret) {
      throw new BadRequestException('Primero genera el código QR (paso de configuración)');
    }
    if (!verifyTotp(user.mfaPendingSecret, code)) {
      throw new BadRequestException('El código no es correcto. Comprueba la hora del dispositivo e inténtalo de nuevo.');
    }
    const recoveryCodes = Array.from({ length: RECOVERY_CODES }, generateRecoveryCode);
    await this.prisma.user.update({
      where: { id: actor.id },
      data: {
        mfaEnabled: true,
        mfaSecret: user.mfaPendingSecret,
        mfaPendingSecret: null,
        mfaEnabledAt: new Date(),
        mfaRecoveryCodes: recoveryCodes.map(recoveryCodeHash),
      },
    });
    this.audit.record({
      organizationId: actor.organizationId,
      action: 'auth.mfa_enabled',
      actor,
      target: { type: 'user', id: actor.id, label: actor.email },
    });
    return { enabled: true, recoveryCodes };
  }

  /** Desactiva el MFA del propio usuario. Exige la contraseña y un código vigente (o de recuperación). */
  async disable(actor: AuthUser, password: string, code: string) {
    const user = await this.prisma.user.findUniqueOrThrow({ where: { id: actor.id } });
    if (!user.mfaEnabled || !user.mfaSecret) {
      throw new BadRequestException('La verificación en dos pasos no está activada');
    }
    if (!(await bcrypt.compare(password, user.passwordHash))) {
      throw new BadRequestException('La contraseña no es correcta');
    }
    if (!this.codeMatches(user, code)) {
      throw new BadRequestException('El código no es correcto');
    }
    await this.clear(actor.id);
    this.audit.record({
      organizationId: actor.organizationId,
      action: 'auth.mfa_disabled',
      actor,
      target: { type: 'user', id: actor.id, label: actor.email },
    });
    return { enabled: false };
  }

  /** Un ADMIN desactiva el MFA de otro usuario (dispositivo perdido sin códigos de recuperación). */
  async adminDisable(actor: AuthUser, target: { id: string; email: string }): Promise<void> {
    await this.clear(target.id);
    this.audit.record({
      organizationId: actor.organizationId,
      action: 'user.mfa_disabled',
      actor,
      target: { type: 'user', id: target.id, label: target.email },
    });
  }

  private async clear(userId: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: false, mfaSecret: null, mfaPendingSecret: null, mfaEnabledAt: null, mfaRecoveryCodes: [] },
    });
  }

  private codeMatches(user: User, code: string): boolean {
    return user.mfaSecret !== null && verifyTotp(user.mfaSecret, code);
  }

  // -------------------------------------------------- segundo paso del login

  /**
   * Segundo paso del login: valida el token intermedio y el código TOTP (o un
   * código de recuperación). Los fallos cuentan para el bloqueo de la cuenta,
   * así que el código de 6 dígitos no se puede probar por fuerza bruta.
   */
  async completeLogin(mfaToken: string, code: string): Promise<AuthResponse> {
    let payload: MfaTokenPayload;
    try {
      payload = this.jwt.verify<MfaTokenPayload>(mfaToken);
    } catch {
      throw new UnauthorizedException('La sesión de verificación caducó; vuelve a iniciar sesión');
    }
    if (payload.purpose !== 'mfa') {
      throw new UnauthorizedException('Token no válido para la verificación en dos pasos');
    }
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      include: { organization: { select: { isActive: true } } },
    });
    if (!user || !user.isActive || !user.organization.isActive || user.tokenVersion !== payload.ver) {
      throw new UnauthorizedException('La sesión de verificación caducó; vuelve a iniciar sesión');
    }
    if (!user.mfaEnabled || !user.mfaSecret) {
      throw new UnauthorizedException('La verificación en dos pasos no está activada');
    }
    await this.loginProtection.assertNotLocked(user.email);

    const actor = { id: user.id, email: user.email, fullName: user.fullName };
    if (verifyTotp(user.mfaSecret, code)) {
      return this.finishLogin(user, false);
    }
    // Código de recuperación de un solo uso.
    const hash = recoveryCodeHash(code);
    if (normalizeRecoveryCode(code).length >= 10 && user.mfaRecoveryCodes.includes(hash)) {
      const remaining = user.mfaRecoveryCodes.filter((h) => h !== hash);
      await this.prisma.user.update({ where: { id: user.id }, data: { mfaRecoveryCodes: remaining } });
      this.audit.record({
        organizationId: user.organizationId,
        action: 'auth.mfa_recovery_used',
        actor,
        target: { type: 'user', id: user.id, label: user.email },
        detail: { recoveryCodesLeft: remaining.length },
      });
      return this.finishLogin(user, true);
    }

    await this.loginProtection.recordFailure(user.email);
    throw new UnauthorizedException('El código no es correcto');
  }

  private async finishLogin(user: User, usedRecoveryCode: boolean): Promise<AuthResponse> {
    await this.loginProtection.reset(user.email);
    await this.prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
    this.audit.record({
      organizationId: user.organizationId,
      action: 'auth.login',
      actor: { id: user.id, email: user.email, fullName: user.fullName },
      detail: { mfa: true, ...(usedRecoveryCode ? { recoveryCode: true } : {}) },
    });
    return this.auth.buildAuthResponse(user);
  }
}
