import { FindingCategory, FindingSeverity, FindingStatus } from '@prisma/client';
import { AttackPathsService } from './attack-paths.service';

describe('AttackPathsService', () => {
  let service: AttackPathsService;
  let prismaMock: {
    finding: {
      findMany: jest.Mock;
    };
  };

  beforeEach(() => {
    prismaMock = {
      finding: {
        findMany: jest.fn(),
      },
    };
    service = new AttackPathsService(prismaMock as any);
  });

  it('returns empty array when no open findings exist', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([]);

    const result = await service.analyzeAttackPaths('org-1');
    expect(result).toEqual([]);
    expect(prismaMock.finding.findMany).toHaveBeenCalledWith({
      where: {
        organizationId: 'org-1',
        status: { in: [FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.VERIFYING] },
      },
      select: expect.any(Object),
    });
  });

  it('identifies AP-PAYMENT-FRAUD when external scripts without SRI and CSP missing/unsafe are present', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([
      {
        id: 'f-1',
        assetId: 'asset-store',
        ruleId: 'WEB-SRI-MISSING-EXTERNAL-SCRIPT',
        title: 'Script externo sin integridad Subresource Integrity (SRI)',
        severity: FindingSeverity.MEDIUM,
        category: FindingCategory.VULNERABLE_SOFTWARE,
        location: 'https://store.example.com/checkout',
        asset: { id: 'asset-store', value: 'store.example.com', name: 'Tienda Online', type: 'DOMAIN' },
      },
      {
        id: 'f-2',
        assetId: 'asset-store',
        ruleId: 'HDR-CSP-MISSING',
        title: 'Cabecera Content-Security-Policy (CSP) ausente',
        severity: FindingSeverity.MEDIUM,
        category: FindingCategory.HTTP_HEADERS,
        location: 'https://store.example.com/',
        asset: { id: 'asset-store', value: 'store.example.com', name: 'Tienda Online', type: 'DOMAIN' },
      },
    ]);

    const result = await service.analyzeAttackPaths('org-1', 'asset-store');
    expect(result).toHaveLength(1);
    const path = result[0];
    expect(path.id).toBe('AP-PAYMENT-FRAUD');
    expect(path.category).toBe('PAYMENT_FRAUD');
    expect(path.severity).toBe('CRITICAL');
    expect(path.assetValue).toBe('store.example.com');
    expect(path.killChainSteps).toHaveLength(3);
    expect(path.killChainSteps[0].matched).toBe(true);
    expect(path.killChainSteps[1].matched).toBe(true);
    expect(path.activeFindings).toHaveLength(2);
    expect(path.recommendedActions.length).toBeGreaterThan(0);
  });

  it('identifies AP-STORE-TAKEOVER when admin panel is exposed with XMLRPC and user enumeration', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([
      {
        id: 'f-1',
        assetId: 'asset-1',
        ruleId: 'PATH-ADMIN-PANEL',
        title: 'Panel administrativo expuesto públicamente',
        severity: FindingSeverity.HIGH,
        category: FindingCategory.SENSITIVE_PATH,
        location: 'https://tienda.com/admin',
        asset: { id: 'asset-1', value: 'tienda.com', name: 'Tienda', type: 'DOMAIN' },
      },
      {
        id: 'f-2',
        assetId: 'asset-1',
        ruleId: 'CMS-WP-USER-ENUMERATION',
        title: 'Enumeración de usuarios WordPress expuesta',
        severity: FindingSeverity.MEDIUM,
        category: FindingCategory.SENSITIVE_PATH,
        location: 'https://tienda.com/wp-json/wp/v2/users',
        asset: { id: 'asset-1', value: 'tienda.com', name: 'Tienda', type: 'DOMAIN' },
      },
      {
        id: 'f-3',
        assetId: 'asset-1',
        ruleId: 'CMS-WP-XMLRPC-ENABLED',
        title: 'XML-RPC habilitado permitiendo ataques multicall',
        severity: FindingSeverity.HIGH,
        category: FindingCategory.EXPOSED_SERVICE,
        location: 'https://tienda.com/xmlrpc.php',
        asset: { id: 'asset-1', value: 'tienda.com', name: 'Tienda', type: 'DOMAIN' },
      },
    ]);

    const result = await service.analyzeAttackPaths('org-1');
    const storePath = result.find((p) => p.id === 'AP-STORE-TAKEOVER');
    expect(storePath).toBeDefined();
    expect(storePath?.severity).toBe('CRITICAL');
    expect(storePath?.killChainSteps.every((s) => s.matched)).toBe(true);
  });

  it('identifies AP-BRAND-IMPERSONATION when DMARC and SPF are missing or permissive', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([
      {
        id: 'f-dmarc',
        assetId: 'asset-mail',
        ruleId: 'MAIL-DMARC-MISSING',
        title: 'Registro DMARC no configurado',
        severity: FindingSeverity.HIGH,
        category: FindingCategory.EMAIL_SECURITY,
        location: '_dmarc.example.com',
        asset: { id: 'asset-mail', value: 'example.com', name: 'Dominio', type: 'DOMAIN' },
      },
      {
        id: 'f-spf',
        assetId: 'asset-mail',
        ruleId: 'MAIL-SPF-PASS-ALL',
        title: 'SPF permisivo (+all)',
        severity: FindingSeverity.HIGH,
        category: FindingCategory.EMAIL_SECURITY,
        location: 'example.com',
        asset: { id: 'asset-mail', value: 'example.com', name: 'Dominio', type: 'DOMAIN' },
      },
    ]);

    const result = await service.analyzeAttackPaths('org-1');
    const brandPath = result.find((p) => p.id === 'AP-BRAND-IMPERSONATION');
    expect(brandPath).toBeDefined();
    expect(brandPath?.severity).toBe('HIGH');
    expect(brandPath?.remediationEffort).toBe('QUICK_WIN');
    expect(brandPath?.quickWinsAvailable).toBeGreaterThan(0);
  });

  it('identifies AP-DATA-EXFILTRATION when source maps or .env files are exposed', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([
      {
        id: 'f-sm',
        assetId: 'asset-app',
        ruleId: 'WEB-SOURCEMAPS-EXPOSED',
        title: 'Archivos Source Maps expuestos',
        severity: FindingSeverity.MEDIUM,
        category: FindingCategory.SENSITIVE_PATH,
        location: 'https://app.com/main.js.map',
        asset: { id: 'asset-app', value: 'app.com', name: 'App', type: 'DOMAIN' },
      },
      {
        id: 'f-env',
        assetId: 'asset-app',
        ruleId: 'PATH-ENV-EXPOSED',
        title: 'Archivo de variables de entorno .env expuesto',
        severity: FindingSeverity.CRITICAL,
        category: FindingCategory.SENSITIVE_PATH,
        location: 'https://app.com/.env',
        asset: { id: 'asset-app', value: 'app.com', name: 'App', type: 'DOMAIN' },
      },
    ]);

    const result = await service.analyzeAttackPaths('org-1');
    const dataPath = result.find((p) => p.id === 'AP-DATA-EXFILTRATION');
    expect(dataPath).toBeDefined();
    expect(dataPath?.severity).toBe('CRITICAL');
  });

  it('identifies AP-INFRASTRUCTURE-COMPROMISE when exposed database or SSH ports exist', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([
      {
        id: 'f-port',
        assetId: 'asset-server',
        ruleId: 'PORT-EXPOSED-DATABASE',
        title: 'Puerto de Base de Datos PostgreSQL (5432) expuesto a Internet',
        severity: FindingSeverity.CRITICAL,
        category: FindingCategory.EXPOSED_SERVICE,
        location: '198.51.100.10:5432',
        asset: { id: 'asset-server', value: '198.51.100.10', name: 'DB Server', type: 'IP' },
      },
    ]);

    const result = await service.analyzeAttackPaths('org-1');
    const infraPath = result.find((p) => p.id === 'AP-INFRASTRUCTURE-COMPROMISE');
    expect(infraPath).toBeDefined();
    expect(infraPath?.severity).toBe('CRITICAL');
    expect(infraPath?.remediationEffort).toBe('QUICK_WIN');
  });

  it('identifies AP-SUBDOMAIN-TAKEOVER when vulnerable CNAME is detected', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([
      {
        id: 'f-sub',
        assetId: 'asset-sub',
        ruleId: 'SUBDOMAIN-TAKEOVER-RISK',
        title: 'Riesgo de Subdomain Takeover en registro CNAME huérfano',
        severity: FindingSeverity.HIGH,
        category: FindingCategory.EXPOSED_SERVICE,
        location: 'promo.example.com CNAME unclaimed.github.io',
        asset: { id: 'asset-sub', value: 'promo.example.com', name: 'Promo Subdomain', type: 'SUBDOMAIN' },
      },
    ]);

    const result = await service.analyzeAttackPaths('org-1');
    const subPath = result.find((p) => p.id === 'AP-SUBDOMAIN-TAKEOVER');
    expect(subPath).toBeDefined();
    expect(subPath?.severity).toBe('HIGH');
  });

  it('orders multiple attack paths by severity descending', async () => {
    prismaMock.finding.findMany.mockResolvedValueOnce([
      // High severity path (Brand Impersonation)
      {
        id: 'f-dmarc',
        assetId: 'asset-1',
        ruleId: 'MAIL-DMARC-MISSING',
        title: 'DMARC missing',
        severity: FindingSeverity.HIGH,
        category: FindingCategory.EMAIL_SECURITY,
        location: 'example.com',
        asset: { id: 'asset-1', value: 'example.com', name: 'Web', type: 'DOMAIN' },
      },
      {
        id: 'f-spf',
        assetId: 'asset-1',
        ruleId: 'MAIL-SPF-MISSING',
        title: 'SPF missing',
        severity: FindingSeverity.HIGH,
        category: FindingCategory.EMAIL_SECURITY,
        location: 'example.com',
        asset: { id: 'asset-1', value: 'example.com', name: 'Web', type: 'DOMAIN' },
      },
      // Critical severity path (Infrastructure Compromise)
      {
        id: 'f-db',
        assetId: 'asset-1',
        ruleId: 'PORT-EXPOSED-DATABASE',
        title: 'DB Exposed',
        severity: FindingSeverity.CRITICAL,
        category: FindingCategory.EXPOSED_SERVICE,
        location: '5432',
        asset: { id: 'asset-1', value: 'example.com', name: 'Web', type: 'DOMAIN' },
      },
    ]);

    const result = await service.analyzeAttackPaths('org-1');
    expect(result.length).toBeGreaterThanOrEqual(2);
    expect(result[0].severity).toBe('CRITICAL');
    expect(result[1].severity).toBe('HIGH');
  });
});
