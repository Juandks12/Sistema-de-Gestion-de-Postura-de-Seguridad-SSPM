import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AccountTokenType } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { MailerService } from '../common/mail/mailer.service';
import { PrismaService } from '../prisma/prisma.service';
import { AccountTokensService, accountTokenHash } from './account-tokens.service';
import { AuthService } from './auth.service';

describe('AccountTokensService (Email Verification & Email Change)', () => {
  let service: AccountTokensService;
  let prismaMock: {
    accountToken: {
      updateMany: jest.Mock;
      create: jest.Mock;
      findFirst: jest.Mock;
      update: jest.Mock;
    };
    user: {
      findUnique: jest.Mock;
      update: jest.Mock;
    };
    loginAttempt: {
      deleteMany: jest.Mock;
    };
    $transaction: jest.Mock;
  };
  let configMock: { get: jest.Mock };
  let mailerMock: { send: jest.Mock; enabled: boolean };
  let auditMock: { record: jest.Mock };
  let authMock: { buildAuthResponse: jest.Mock; hashPassword: jest.Mock };

  const actor: AuthUser = {
    id: 'user-1',
    organizationId: 'org-1',
    role: 'ADMIN',
    fullName: 'Ana Admin',
    email: 'ana@admin.local',
  };

  beforeEach(() => {
    prismaMock = {
      accountToken: {
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        create: jest.fn().mockResolvedValue({ id: 'token-row-1' }),
        findFirst: jest.fn(),
        update: jest.fn().mockResolvedValue({}),
      },
      user: {
        findUnique: jest.fn(),
        update: jest.fn().mockResolvedValue({}),
      },
      loginAttempt: {
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
      },
      $transaction: jest.fn().mockImplementation(async (arg) => {
        if (typeof arg === 'function') {
          return arg(prismaMock);
        }
        return Promise.all(arg);
      }),
    };

    configMock = {
      get: jest.fn((key: string) => {
        if (key === 'APP_URL') return 'https://sspm.test';
        if (key === 'EMAIL_VERIFICATION_TTL_HOURS') return 24;
        if (key === 'EMAIL_CHANGE_TTL_HOURS') return 2;
        return undefined;
      }),
    };

    mailerMock = {
      send: jest.fn().mockResolvedValue({ ok: true, status: 'SENT' }),
      enabled: true,
    };

    auditMock = {
      record: jest.fn(),
    };

    authMock = {
      buildAuthResponse: jest.fn().mockReturnValue({ accessToken: 'new-jwt-token' }),
      hashPassword: jest.fn().mockResolvedValue('hashed-pass'),
    };

    service = new AccountTokensService(
      prismaMock as unknown as PrismaService,
      configMock as unknown as ConfigService,
      mailerMock as unknown as MailerService,
      auditMock as unknown as AuditService,
      authMock as unknown as AuthService,
    );
  });

  describe('sendRegistrationVerification', () => {
    it('no hace nada si el mailer está deshabilitado', async () => {
      mailerMock.enabled = false;
      await service.sendRegistrationVerification({
        id: 'user-1',
        email: 'user@test.local',
        fullName: 'User Test',
        organizationId: 'org-1',
      });
      expect(prismaMock.accountToken.create).not.toHaveBeenCalled();
      expect(mailerMock.send).not.toHaveBeenCalled();
    });

    it('emite token, envía correo y registra auditoría cuando mailer está activo', async () => {
      mailerMock.enabled = true;
      await service.sendRegistrationVerification({
        id: 'user-1',
        email: 'user@test.local',
        fullName: 'User Test',
        organizationId: 'org-1',
      });

      expect(prismaMock.accountToken.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            organizationId: 'org-1',
            type: AccountTokenType.EMAIL_VERIFICATION,
            email: 'user@test.local',
            userId: 'user-1',
          }),
        }),
      );
      expect(mailerMock.send).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'user@test.local',
          subject: '[SSPM] Verifica tu correo electrónico',
        }),
      );
      expect(auditMock.record).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'auth.email_verification_requested',
          organizationId: 'org-1',
        }),
      );
    });
  });

  describe('verifyEmail', () => {
    it('falla con 400 si el token no existe o no tiene userId', async () => {
      prismaMock.accountToken.findFirst.mockResolvedValue(null);
      await expect(service.verifyEmail('invalid-token')).rejects.toThrow(BadRequestException);
    });

    it('verifica al usuario y registra auditoría con token válido', async () => {
      prismaMock.accountToken.findFirst.mockResolvedValue({
        id: 'tok-1',
        type: AccountTokenType.EMAIL_VERIFICATION,
        userId: 'u-1',
      });
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'u-1',
        isActive: true,
        organizationId: 'org-1',
        email: 'u1@test.local',
        fullName: 'User One',
        organization: { isActive: true },
      });

      const res = await service.verifyEmail('valid-token');
      expect(res).toEqual({ message: 'Correo electrónico verificado correctamente.', emailVerified: true });
      expect(prismaMock.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'u-1' },
          data: expect.objectContaining({ emailVerifiedAt: expect.any(Date) }),
        }),
      );
      expect(auditMock.record).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'auth.email_verified',
          organizationId: 'org-1',
        }),
      );
    });
  });

  describe('resendVerification', () => {
    it('indica si el correo ya está verificado', async () => {
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'u-1',
        email: 'u1@test.local',
        isActive: true,
        emailVerifiedAt: new Date(),
        organization: { isActive: true },
      });

      const res = await service.resendVerification('u1@test.local');
      expect(res).toMatchObject({ emailVerified: true });
      expect(mailerMock.send).not.toHaveBeenCalled();
    });

    it('auto-verifica si el mailer está deshabilitado', async () => {
      mailerMock.enabled = false;
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'u-1',
        email: 'u1@test.local',
        isActive: true,
        emailVerifiedAt: null,
        organization: { isActive: true },
      });

      const res = await service.resendVerification('u1@test.local');
      expect(res).toMatchObject({ emailVerified: true, emailEnabled: false });
      expect(prismaMock.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'u-1' },
          data: expect.objectContaining({ emailVerifiedAt: expect.any(Date) }),
        }),
      );
    });

    it('emite token y envía correo si mailer está habilitado', async () => {
      mailerMock.enabled = true;
      prismaMock.user.findUnique.mockResolvedValue({
        id: 'u-1',
        email: 'u1@test.local',
        fullName: 'User Test',
        organizationId: 'org-1',
        isActive: true,
        emailVerifiedAt: null,
        organization: { isActive: true },
      });

      const res = await service.resendVerification('u1@test.local');
      expect(res).toMatchObject({ emailEnabled: true });
      expect(mailerMock.send).toHaveBeenCalled();
    });
  });

  describe('requestEmailChange', () => {
    it('rechaza si el nuevo correo es igual al actual', async () => {
      await expect(service.requestEmailChange(actor, 'ana@admin.local', 'Password123!')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('rechaza si la contraseña actual no es correcta', async () => {
      const hash = await bcrypt.hash('CorrectPassword123!', 10);
      prismaMock.user.findUnique.mockResolvedValueOnce({ id: actor.id, passwordHash: hash });

      await expect(service.requestEmailChange(actor, 'nuevo@admin.local', 'WrongPass!')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('rechaza con 409 si el nuevo correo ya está registrado', async () => {
      const hash = await bcrypt.hash('Password123!', 10);
      prismaMock.user.findUnique
        .mockResolvedValueOnce({ id: actor.id, passwordHash: hash })
        .mockResolvedValueOnce({ id: 'other-user', email: 'nuevo@admin.local' });

      await expect(service.requestEmailChange(actor, 'nuevo@admin.local', 'Password123!')).rejects.toThrow(
        ConflictException,
      );
    });

    it('actualiza de inmediato si el mailer no está configurado', async () => {
      mailerMock.enabled = false;
      const hash = await bcrypt.hash('Password123!', 10);
      prismaMock.user.findUnique
        .mockResolvedValueOnce({ id: actor.id, passwordHash: hash })
        .mockResolvedValueOnce(null);

      const res = await service.requestEmailChange(actor, 'nuevo@admin.local', 'Password123!');
      expect(res).toEqual({
        immediate: true,
        message: 'Correo electrónico modificado exitosamente.',
        newEmail: 'nuevo@admin.local',
      });
      expect(prismaMock.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ email: 'nuevo@admin.local', pendingEmail: null }),
        }),
      );
    });

    it('envía correo de confirmación al nuevo correo y aviso de seguridad al antiguo', async () => {
      mailerMock.enabled = true;
      const hash = await bcrypt.hash('Password123!', 10);
      prismaMock.user.findUnique
        .mockResolvedValueOnce({ id: actor.id, passwordHash: hash })
        .mockResolvedValueOnce(null);

      const res = await service.requestEmailChange(actor, 'nuevo@admin.local', 'Password123!');
      expect(res).toEqual({
        immediate: false,
        message: 'Se ha enviado un enlace de confirmación a tu nueva dirección de correo.',
        newEmail: 'nuevo@admin.local',
      });
      expect(prismaMock.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: actor.id },
          data: { pendingEmail: 'nuevo@admin.local' },
        }),
      );
      // Se enviaron dos correos (confirmación y aviso)
      expect(mailerMock.send).toHaveBeenCalledTimes(2);
      expect(auditMock.record).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'auth.email_change_requested' }),
      );
    });
  });

  describe('confirmEmailChange', () => {
    it('falla con 400 si el token no existe o caducó', async () => {
      prismaMock.accountToken.findFirst.mockResolvedValue(null);
      await expect(service.confirmEmailChange('invalid-token')).rejects.toThrow(BadRequestException);
    });

    it('falla con 409 si el correo ya fue tomado por otro usuario', async () => {
      prismaMock.accountToken.findFirst.mockResolvedValue({
        id: 'tok-2',
        userId: 'u-1',
        email: 'ocupado@admin.local',
      });
      prismaMock.user.findUnique
        .mockResolvedValueOnce({ id: 'u-1', isActive: true, organization: { isActive: true } })
        .mockResolvedValueOnce({ id: 'u-other', email: 'ocupado@admin.local' });

      await expect(service.confirmEmailChange('tok-2')).rejects.toThrow(ConflictException);
    });

    it('consume token, actualiza correo del usuario y emite nueva sesión', async () => {
      prismaMock.accountToken.findFirst.mockResolvedValue({
        id: 'tok-2',
        userId: 'u-1',
        email: 'nuevo@admin.local',
      });
      prismaMock.user.findUnique
        .mockResolvedValueOnce({ id: 'u-1', isActive: true, email: 'viejo@admin.local', organization: { isActive: true } })
        .mockResolvedValueOnce(null);
      prismaMock.user.update.mockResolvedValue({
        id: 'u-1',
        email: 'nuevo@admin.local',
        tokenVersion: 2,
      });

      const res = await service.confirmEmailChange('tok-2');
      expect(res).toEqual({ accessToken: 'new-jwt-token' });
      expect(prismaMock.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'u-1' },
          data: expect.objectContaining({
            email: 'nuevo@admin.local',
            pendingEmail: null,
            emailVerifiedAt: expect.any(Date),
          }),
        }),
      );
      expect(auditMock.record).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'auth.email_changed' }),
      );
    });
  });

  describe('cancelPendingEmailChange', () => {
    it('limpia pendingEmail y caduca tokens en vuelo', async () => {
      const res = await service.cancelPendingEmailChange(actor);
      expect(res).toEqual({ message: 'Solicitud de cambio de correo cancelada.' });
      expect(prismaMock.user.update).toHaveBeenCalledWith({
        where: { id: actor.id },
        data: { pendingEmail: null },
      });
      expect(prismaMock.accountToken.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            userId: actor.id,
            type: AccountTokenType.EMAIL_CHANGE,
          }),
        }),
      );
    });
  });
});
