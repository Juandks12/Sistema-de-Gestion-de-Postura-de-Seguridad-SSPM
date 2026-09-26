import { BadRequestException, ConflictException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AccountToken, AccountTokenType, Prisma, UserRole } from '@prisma/client';
import { createHash, randomBytes } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { MailerService } from '../common/mail/mailer.service';
import { PrismaService } from '../prisma/prisma.service';
import { invitationEmail, passwordResetEmail, ROLE_EMAIL_LABEL } from './account-emails';
import { AuthResponse, AuthService } from './auth.service';
import { loginAttemptKey } from './login-protection.service';

export function accountTokenHash(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

const invitationSelect = {
  id: true,
  email: true,
  role: true,
  expiresAt: true,
  usedAt: true,
  deliveryStatus: true,
  deliveryError: true,
  createdAt: true,
  createdBy: { select: { id: true, fullName: true } },
} satisfies Prisma.AccountTokenSelect;

/**
 * Tokens de un solo uso enviados por correo (sección 11.1): restablecer la
 * contraseña e invitaciones a la organización. En la base de datos solo vive
 * el hash sha256 del token; el valor real va únicamente en el enlace.
 */
@Injectable()
export class AccountTokensService {
  private readonly logger = new Logger(AccountTokensService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly mailer: MailerService,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
  ) {}

  private get resetTtlMinutes(): number {
    return this.config.get<number>('PASSWORD_RESET_TTL_MINUTES') ?? 30;
  }

  private get invitationTtlHours(): number {
    return this.config.get<number>('INVITATION_TTL_HOURS') ?? 72;
  }

  private appUrl(path: string): string {
    const base = (this.config.get<string>('APP_URL') ?? '').replace(/\/+$/, '');
    return `${base}${path}`;
  }

  get emailEnabled(): boolean {
    return this.mailer.enabled;
  }

  private normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  /** Crea el token, invalida los anteriores del mismo tipo y destino, y devuelve el valor en claro. */
  private async issue(data: {
    organizationId: string;
    type: AccountTokenType;
    email: string;
    userId?: string;
    role?: UserRole;
    createdById?: string;
    ttlMs: number;
  }): Promise<{ token: string; row: AccountToken }> {
    const token = randomBytes(32).toString('hex');
    const [, row] = await this.prisma.$transaction([
      // Solo puede haber un token vigente por destino: emitir uno nuevo caduca los anteriores.
      this.prisma.accountToken.updateMany({
        where: { type: data.type, email: data.email, usedAt: null, expiresAt: { gt: new Date() } },
        data: { expiresAt: new Date() },
      }),
      this.prisma.accountToken.create({
        data: {
          organizationId: data.organizationId,
          type: data.type,
          tokenHash: accountTokenHash(token),
          email: data.email,
          userId: data.userId,
          role: data.role,
          createdById: data.createdById,
          expiresAt: new Date(Date.now() + data.ttlMs),
        },
      }),
    ]);
    return { token, row };
  }

  /** Token vigente (no usado, no caducado) o null. */
  private findValid(type: AccountTokenType, token: string) {
    return this.prisma.accountToken.findFirst({
      where: { type, tokenHash: accountTokenHash(token), usedAt: null, expiresAt: { gt: new Date() } },
    });
  }

  private async recordDelivery(id: string, result: { status: string; error?: string }): Promise<void> {
    await this.prisma.accountToken.update({
      where: { id },
      data: { deliveryStatus: result.status, deliveryError: result.error?.slice(0, 500) ?? null },
    });
  }

  // ------------------------------------------------- restablecer contraseña

  /**
   * Solicitud de restablecimiento. La respuesta es siempre la misma exista o
   * no la cuenta, para no revelar qué correos están registrados.
   */
  async requestPasswordReset(rawEmail: string): Promise<{ message: string; emailEnabled: boolean }> {
    const email = this.normalizeEmail(rawEmail);
    const message =
      'Si el correo está registrado, recibirás un enlace para restablecer la contraseña en unos minutos.';
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: { organization: { select: { isActive: true } } },
    });
    if (user && user.isActive && user.organization.isActive) {
      const { token, row } = await this.issue({
        organizationId: user.organizationId,
        type: AccountTokenType.PASSWORD_RESET,
        email,
        userId: user.id,
        ttlMs: this.resetTtlMinutes * 60 * 1000,
      });
      const url = this.appUrl(`/reset-password?token=${token}`);
      const result = await this.mailer.send(passwordResetEmail(email, user.fullName, url, this.resetTtlMinutes));
      await this.recordDelivery(row.id, result);
      if (!result.ok) {
        this.logger.warn(`Restablecimiento para ${email}: correo ${result.status} (${result.error ?? ''})`);
      }
      this.audit.record({
        organizationId: user.organizationId,
        action: 'auth.password_reset_requested',
        actor: null,
        target: { type: 'user', id: user.id, label: email },
        detail: { delivery: result.status },
      });
    }
    return { message, emailEnabled: this.mailer.enabled };
  }

  /** Canjea el token y fija la contraseña nueva. Cierra las demás sesiones y desbloquea la cuenta. */
  async resetPassword(token: string, newPassword: string): Promise<AuthResponse> {
    const row = await this.findValid(AccountTokenType.PASSWORD_RESET, token);
    if (!row || !row.userId) {
      throw new BadRequestException('El enlace no es válido o ya caducó. Solicita uno nuevo.');
    }
    const user = await this.prisma.user.findUnique({ where: { id: row.userId } });
    if (!user || !user.isActive) {
      throw new BadRequestException('El enlace no es válido o ya caducó. Solicita uno nuevo.');
    }
    const passwordHash = await this.auth.hashPassword(newPassword);
    const [updated] = await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: user.id },
        data: { passwordHash, passwordChangedAt: new Date(), tokenVersion: { increment: 1 } },
      }),
      this.prisma.accountToken.update({ where: { id: row.id }, data: { usedAt: new Date() } }),
      this.prisma.loginAttempt.deleteMany({ where: { key: loginAttemptKey(user.email) } }),
    ]);
    this.audit.record({
      organizationId: user.organizationId,
      action: 'auth.password_reset',
      actor: { id: user.id, email: user.email, fullName: user.fullName },
      target: { type: 'user', id: user.id, label: user.email },
    });
    return this.auth.buildAuthResponse(updated);
  }

  // ------------------------------------------------------------ invitaciones

  listInvitations(organizationId: string) {
    return this.prisma.accountToken
      .findMany({
        where: { organizationId, type: AccountTokenType.INVITATION, usedAt: null },
        select: invitationSelect,
        orderBy: { createdAt: 'desc' },
      })
      .then((rows) =>
        rows.map((r) => ({ ...r, expired: r.expiresAt.getTime() < Date.now() })),
      );
  }

  async invite(actor: AuthUser, rawEmail: string, role: UserRole) {
    const email = this.normalizeEmail(rawEmail);
    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new ConflictException('Ya existe un usuario con ese correo electrónico');
    }
    const { token, row } = await this.issue({
      organizationId: actor.organizationId,
      type: AccountTokenType.INVITATION,
      email,
      role,
      createdById: actor.id,
      ttlMs: this.invitationTtlHours * 60 * 60 * 1000,
    });
    const result = await this.sendInvitation(actor, email, role, token);
    await this.recordDelivery(row.id, result);
    this.audit.record({
      organizationId: actor.organizationId,
      action: 'user.invite',
      actor,
      target: { type: 'invitation', id: row.id, label: email },
      detail: { role, delivery: result.status },
    });
    const [saved] = await this.listInvitationRows(actor.organizationId, row.id);
    return saved;
  }

  private listInvitationRows(organizationId: string, id: string) {
    return this.prisma.accountToken.findMany({ where: { id, organizationId }, select: invitationSelect });
  }

  private async sendInvitation(actor: AuthUser, email: string, role: UserRole, token: string) {
    const org = await this.prisma.organization.findUniqueOrThrow({
      where: { id: actor.organizationId },
      select: { name: true },
    });
    const url = this.appUrl(`/invitation?token=${token}`);
    return this.mailer.send(
      invitationEmail(email, org.name, actor.fullName, ROLE_EMAIL_LABEL[role] ?? role, url, this.invitationTtlHours),
    );
  }

  /** Reenvía una invitación pendiente con un token nuevo (el anterior queda caducado). */
  async resendInvitation(actor: AuthUser, id: string) {
    const row = await this.prisma.accountToken.findFirst({
      where: { id, organizationId: actor.organizationId, type: AccountTokenType.INVITATION, usedAt: null },
    });
    if (!row || !row.role) {
      throw new NotFoundException('Invitación no encontrada');
    }
    const { token, row: fresh } = await this.issue({
      organizationId: actor.organizationId,
      type: AccountTokenType.INVITATION,
      email: row.email,
      role: row.role,
      createdById: actor.id,
      ttlMs: this.invitationTtlHours * 60 * 60 * 1000,
    });
    const result = await this.sendInvitation(actor, row.email, row.role, token);
    await this.recordDelivery(fresh.id, result);
    this.audit.record({
      organizationId: actor.organizationId,
      action: 'user.invite_resent',
      actor,
      target: { type: 'invitation', id: fresh.id, label: row.email },
      detail: { role: row.role, delivery: result.status },
    });
    const [saved] = await this.listInvitationRows(actor.organizationId, fresh.id);
    return saved;
  }

  async cancelInvitation(actor: AuthUser, id: string): Promise<void> {
    const row = await this.prisma.accountToken.findFirst({
      where: { id, organizationId: actor.organizationId, type: AccountTokenType.INVITATION, usedAt: null },
    });
    if (!row) {
      throw new NotFoundException('Invitación no encontrada');
    }
    await this.prisma.accountToken.delete({ where: { id } });
    this.audit.record({
      organizationId: actor.organizationId,
      action: 'user.invite_cancelled',
      actor,
      target: { type: 'invitation', id, label: row.email },
    });
  }

  /** Datos públicos de una invitación vigente (pantalla de aceptación). */
  async invitationInfo(token: string) {
    const row = await this.findValid(AccountTokenType.INVITATION, token);
    if (!row) {
      throw new NotFoundException('La invitación no es válida o ya caducó. Pide que te la reenvíen.');
    }
    const org = await this.prisma.organization.findUniqueOrThrow({
      where: { id: row.organizationId },
      select: { name: true },
    });
    return { email: row.email, role: row.role, organizationName: org.name, expiresAt: row.expiresAt };
  }

  /** Acepta la invitación: crea el usuario con su contraseña e inicia sesión. */
  async acceptInvitation(token: string, fullName: string, password: string): Promise<AuthResponse> {
    const row = await this.findValid(AccountTokenType.INVITATION, token);
    if (!row || !row.role) {
      throw new BadRequestException('La invitación no es válida o ya caducó. Pide que te la reenvíen.');
    }
    const exists = await this.prisma.user.findUnique({ where: { email: row.email } });
    if (exists) {
      throw new ConflictException('Ya existe un usuario con ese correo electrónico');
    }
    const passwordHash = await this.auth.hashPassword(password);
    const user = await this.prisma.$transaction(async (tx) => {
      const created = await tx.user.create({
        data: {
          email: row.email,
          fullName,
          passwordHash,
          role: row.role!,
          organizationId: row.organizationId,
        },
      });
      // Se marcan usadas todas las invitaciones de ese correo (también las reenviadas y caducadas).
      await tx.accountToken.updateMany({
        where: { type: AccountTokenType.INVITATION, email: row.email, usedAt: null },
        data: { usedAt: new Date() },
      });
      await tx.accountToken.update({ where: { id: row.id }, data: { userId: created.id } });
      return created;
    });
    this.audit.record({
      organizationId: user.organizationId,
      action: 'user.invite_accepted',
      actor: { id: user.id, email: user.email, fullName: user.fullName },
      target: { type: 'user', id: user.id, label: user.email },
      detail: { role: user.role },
    });
    return this.auth.buildAuthResponse(user);
  }
}
