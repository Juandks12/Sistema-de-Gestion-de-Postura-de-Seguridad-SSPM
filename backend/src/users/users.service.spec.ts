import { UserRole } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthService } from '../auth/auth.service';
import { MfaService } from '../auth/mfa.service';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from './users.service';

describe('UsersService - findAssignees', () => {
  let service: UsersService;
  let prismaMock: { user: { findMany: jest.Mock } };

  beforeEach(() => {
    prismaMock = {
      user: {
        findMany: jest.fn(),
      },
    };
    service = new UsersService(
      prismaMock as unknown as PrismaService,
      {} as unknown as AuthService,
      {} as unknown as MfaService,
      {} as unknown as AuditService,
    );
  });

  it('lists active members of the organization sorted by fullName', async () => {
    prismaMock.user.findMany.mockResolvedValueOnce([
      { id: 'u-1', fullName: 'Alice Security', email: 'alice@example.com', role: UserRole.ANALYST },
      { id: 'u-2', fullName: 'Bob Admin', email: 'bob@example.com', role: UserRole.ADMIN },
    ]);

    const result = await service.findAssignees('org-1');

    expect(prismaMock.user.findMany).toHaveBeenCalledWith({
      where: { organizationId: 'org-1', isActive: true },
      select: {
        id: true,
        email: true,
        fullName: true,
        role: true,
      },
      orderBy: { fullName: 'asc' },
    });
    expect(result).toHaveLength(2);
    expect(result[0].fullName).toBe('Alice Security');
  });
});
