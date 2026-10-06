import { FindingCategory, FindingSeverity, FindingStatus, Prisma } from '@prisma/client';
import { FindingsService } from './findings.service';
import { UTF8_BOM } from '../common/utils/csv';

describe('FindingsService - exportStream', () => {
  let service: FindingsService;
  let prismaMock: { finding: { findMany: jest.Mock } };

  beforeEach(() => {
    prismaMock = {
      finding: {
        findMany: jest.fn(),
      },
    };
    service = new FindingsService(
      prismaMock as any,
      {} as any,
      {} as any,
    );
  });

  async function readStream(stream: NodeJS.ReadableStream): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of stream) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks).toString('utf-8');
  }

  it('exports empty findings list with BOM and CSV header', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([]);

    const stream = service.exportStream('org-123', {});
    const csv = await readStream(stream);

    expect(csv.startsWith(UTF8_BOM)).toBe(true);
    const lines = csv.slice(UTF8_BOM.length).trim().split('\r\n');
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe(
      'id,rule_id,severity,cvss_score,category,status,title,description,recommendation,asset_name,asset_value,asset_type,location,first_seen_at,last_seen_at,resolved_at,assigned_to,due_date,remediation_note,reviewed_by,review_note',
    );
  });

  it('formats finding records with RFC 4180 escaping and values', async () => {
    const firstSeen = new Date('2026-10-01T10:00:00.000Z');
    const lastSeen = new Date('2026-10-05T15:30:00.000Z');
    const dueDate = new Date('2026-10-15T00:00:00.000Z');

    prismaMock.finding.findMany
      .mockResolvedValueOnce([
        {
          id: 'f-1',
          ruleId: 'HDR-HSTS-MISSING',
          severity: FindingSeverity.HIGH,
          cvssScore: new Prisma.Decimal(7.5),
          category: FindingCategory.HTTP_HEADERS,
          status: FindingStatus.IN_PROGRESS,
          title: 'Cabecera HSTS ausente',
          description: 'El servidor no envía Strict-Transport-Security, protección TLS incompleta.',
          recommendation: 'Configurar HSTS con max-age >= 31536000.',
          location: 'https://example.com/',
          firstSeenAt: firstSeen,
          lastSeenAt: lastSeen,
          resolvedAt: null,
          assignedTo: { id: 'u-2', fullName: 'Dev Lead', email: 'dev@example.com' },
          dueDate,
          remediationNote: 'Ticket Jira SEC-104 abierto para configurar Nginx',
          reviewNote: null,
          asset: { id: 'a-1', name: 'Web Principal', value: 'example.com', type: 'DOMAIN' },
          reviewedBy: null,
        },
        {
          id: 'f-2',
          ruleId: 'PORT-TELNET-OPEN',
          severity: FindingSeverity.CRITICAL,
          cvssScore: new Prisma.Decimal(9.8),
          category: FindingCategory.EXPOSED_SERVICE,
          status: FindingStatus.ACCEPTED,
          title: 'Puerto Telnet abierto (inseguro)',
          description: 'Transmisión en texto plano, vulnerable.',
          recommendation: 'Reemplazar con SSH.',
          location: 'tcp/23',
          firstSeenAt: firstSeen,
          lastSeenAt: lastSeen,
          resolvedAt: null,
          assignedTo: null,
          dueDate: null,
          remediationNote: null,
          reviewNote: 'Riesgo aceptado por legado',
          asset: { id: 'a-2', name: null, value: '192.168.1.1', type: 'IP' },
          reviewedBy: { id: 'u-1', email: 'security@example.com', fullName: 'Sec Analyst' },
        },
      ])
      .mockResolvedValueOnce([]);

    const stream = service.exportStream('org-123', {});
    const csv = await readStream(stream);

    expect(csv.startsWith(UTF8_BOM)).toBe(true);
    const lines = csv.slice(UTF8_BOM.length).trim().split('\r\n');
    expect(lines).toHaveLength(3);

    // Verify row 1
    expect(lines[1]).toContain('f-1,HDR-HSTS-MISSING,HIGH,7.5,HTTP_HEADERS,IN_PROGRESS');
    expect(lines[1]).toContain('"El servidor no envía Strict-Transport-Security, protección TLS incompleta."');
    expect(lines[1]).toContain('Dev Lead (dev@example.com)');
    expect(lines[1]).toContain('Ticket Jira SEC-104 abierto para configurar Nginx');
    expect(lines[1]).toContain('example.com,DOMAIN');

    // Verify row 2 (review note, reviewer email)
    expect(lines[2]).toContain('f-2,PORT-TELNET-OPEN,CRITICAL,9.8,EXPOSED_SERVICE,ACCEPTED');
    expect(lines[2]).toContain('security@example.com,Riesgo aceptado por legado');
  });

  it('applies filters for asset, severity, status, assignedToId and date range', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([]);

    const stream = service.exportStream('org-123', {
      assetId: 'asset-99',
      severity: FindingSeverity.CRITICAL,
      status: FindingStatus.OPEN,
      category: FindingCategory.EMAIL_SECURITY,
      assignedToId: 'u-55',
      fromDate: '2026-10-01T00:00:00.000Z',
      toDate: '2026-10-05T23:59:59.000Z',
    });
    await readStream(stream);

    expect(prismaMock.finding.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          organizationId: 'org-123',
          assetId: 'asset-99',
          severity: FindingSeverity.CRITICAL,
          status: FindingStatus.OPEN,
          category: FindingCategory.EMAIL_SECURITY,
          assignedToId: 'u-55',
          firstSeenAt: {
            gte: new Date('2026-10-01T00:00:00.000Z'),
            lte: new Date('2026-10-05T23:59:59.000Z'),
          },
        }),
      }),
    );
  });
});

describe('FindingsService - review & lifecycle', () => {
  let service: FindingsService;
  let prismaMock: {
    finding: { findFirst: jest.Mock; update: jest.Mock };
    user: { findFirst: jest.Mock };
    $transaction: jest.Mock;
  };
  let riskScoresMock: { snapshot: jest.Mock };
  let auditMock: { record: jest.Mock };

  beforeEach(() => {
    prismaMock = {
      finding: {
        findFirst: jest.fn(),
        update: jest.fn(),
      },
      user: {
        findFirst: jest.fn(),
      },
      $transaction: jest.fn((cb) => cb(prismaMock)),
    };
    riskScoresMock = { snapshot: jest.fn().mockResolvedValue({}) };
    auditMock = { record: jest.fn() };
    service = new FindingsService(
      prismaMock as any,
      riskScoresMock as any,
      auditMock as any,
    );
  });

  it('updates status to IN_PROGRESS, sets assignment, due date and remediation note', async () => {
    const actor = {
      id: 'actor-1',
      organizationId: 'org-1',
      email: 'admin@example.com',
      fullName: 'Admin User',
      role: 'ADMIN',
    } as any;

    prismaMock.finding.findFirst.mockResolvedValueOnce({
      id: 'f-100',
      organizationId: 'org-1',
      assetId: 'asset-1',
      status: FindingStatus.OPEN,
      ruleId: 'HDR-HSTS-MISSING',
      location: 'https://test.com',
    });

    prismaMock.user.findFirst.mockResolvedValueOnce({ id: 'u-assigned' });
    prismaMock.finding.update.mockResolvedValueOnce({
      id: 'f-100',
      status: FindingStatus.IN_PROGRESS,
      ruleId: 'HDR-HSTS-MISSING',
      location: 'https://test.com',
      assignedToId: 'u-assigned',
      dueDate: new Date('2026-10-20T00:00:00.000Z'),
      remediationNote: 'En proceso de corrección',
    });

    const result = await service.review(actor, 'f-100', {
      status: FindingStatus.IN_PROGRESS,
      assignedToId: 'u-assigned',
      dueDate: '2026-10-20T00:00:00.000Z',
      remediationNote: 'En proceso de corrección',
    });

    expect(prismaMock.user.findFirst).toHaveBeenCalledWith({
      where: { id: 'u-assigned', organizationId: 'org-1' },
      select: { id: true },
    });
    expect(prismaMock.finding.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'f-100' },
        data: expect.objectContaining({
          status: FindingStatus.IN_PROGRESS,
          assignedTo: { connect: { id: 'u-assigned' } },
          remediationNote: 'En proceso de corrección',
        }),
      }),
    );
    expect(auditMock.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'finding.review',
        organizationId: 'org-1',
      }),
    );
    expect(result.status).toBe(FindingStatus.IN_PROGRESS);
  });

  it('rejects assignment if user does not belong to organization', async () => {
    const actor = {
      id: 'actor-1',
      organizationId: 'org-1',
      email: 'admin@example.com',
      fullName: 'Admin User',
      role: 'ADMIN',
    } as any;

    prismaMock.finding.findFirst.mockResolvedValueOnce({
      id: 'f-100',
      organizationId: 'org-1',
      assetId: 'asset-1',
      status: FindingStatus.OPEN,
    });
    prismaMock.user.findFirst.mockResolvedValueOnce(null);

    await expect(
      service.review(actor, 'f-100', { assignedToId: 'invalid-user' }),
    ).rejects.toThrow('El usuario asignado no pertenece a la organización');
  });
});
