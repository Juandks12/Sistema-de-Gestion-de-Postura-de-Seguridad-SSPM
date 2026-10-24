import { Injectable } from '@nestjs/common';
import { FindingCategory, FindingSeverity, FindingStatus } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { FINDING_RULES, RemediationEffort } from './rules.catalog';

export type AttackPathCategory =
  | 'PAYMENT_FRAUD'
  | 'STORE_TAKEOVER'
  | 'BRAND_IMPERSONATION'
  | 'DATA_EXFILTRATION'
  | 'INFRASTRUCTURE_COMPROMISE'
  | 'SUBDOMAIN_TAKEOVER';

export type AttackPathSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM';

export interface AttackPathKillChainStep {
  order: number;
  phase: string;
  title: string;
  description: string;
  matchedRuleId?: string;
  matched: boolean;
  findingTitle?: string;
  location?: string;
}

export interface AttackPathSummary {
  id: string;
  title: string;
  category: AttackPathCategory;
  severity: AttackPathSeverity;
  narrative: string;
  businessRisk: string;
  estimatedImpact: string;
  assetId?: string;
  assetName?: string;
  assetValue?: string;
  killChainSteps: AttackPathKillChainStep[];
  activeFindings: Array<{
    id: string;
    ruleId: string;
    title: string;
    severity: FindingSeverity;
    location?: string;
    effort: RemediationEffort;
    estimatedMinutes: number;
  }>;
  quickWinsAvailable: number;
  remediationEffort: RemediationEffort;
  recommendedActions: string[];
}

interface CorrelatedFinding {
  id: string;
  assetId: string | null;
  ruleId: string;
  title: string;
  severity: FindingSeverity;
  category: FindingCategory;
  location: string | null;
  asset?: {
    id: string;
    value: string;
    name: string | null;
    type: string;
  } | null;
}

@Injectable()
export class AttackPathsService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Analiza los hallazgos abiertos de una organización (u opcionalmente de un activo específico)
   * y correlaciona combinaciones críticas en Rutas de Ataque compuestas con impacto de negocio.
   */
  async analyzeAttackPaths(
    organizationId: string,
    assetId?: string,
  ): Promise<AttackPathSummary[]> {
    const findings: CorrelatedFinding[] = await this.prisma.finding.findMany({
      where: {
        organizationId,
        ...(assetId ? { assetId } : {}),
        status: { in: [FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.VERIFYING] },
      },
      select: {
        id: true,
        assetId: true,
        ruleId: true,
        title: true,
        severity: true,
        category: true,
        location: true,
        asset: {
          select: {
            id: true,
            value: true,
            name: true,
            type: true,
          },
        },
      },
    });

    if (findings.length === 0) {
      return [];
    }

    const attackPaths: AttackPathSummary[] = [];

    // Si se consulta para toda la organización, agrupamos por activo para generar rutas contextualizadas
    const assetGroups = new Map<string, CorrelatedFinding[]>();
    for (const f of findings) {
      const key = f.assetId || 'global';
      const list = assetGroups.get(key) ?? [];
      list.push(f);
      assetGroups.set(key, list);
    }

    for (const [groupAssetId, assetFindings] of assetGroups.entries()) {
      const targetAsset = assetFindings[0]?.asset;
      const assetContext = {
        assetId: groupAssetId !== 'global' ? groupAssetId : undefined,
        assetName: targetAsset?.name ?? undefined,
        assetValue: targetAsset?.value ?? undefined,
      };

      // 1. AP-PAYMENT-FRAUD: Fraude en Pagos y E-Skimming (Magecart)
      const paymentFraudPath = this.evaluatePaymentFraud(assetFindings, assetContext);
      if (paymentFraudPath) attackPaths.push(paymentFraudPath);

      // 2. AP-STORE-TAKEOVER: Toma de Control de Tienda y Panel Administrativo
      const storeTakeoverPath = this.evaluateStoreTakeover(assetFindings, assetContext);
      if (storeTakeoverPath) attackPaths.push(storeTakeoverPath);

      // 3. AP-BRAND-IMPERSONATION: Suplantación de Marca y Fraude Facturero (BEC)
      const brandImpersonationPath = this.evaluateBrandImpersonation(assetFindings, assetContext);
      if (brandImpersonationPath) attackPaths.push(brandImpersonationPath);

      // 4. AP-DATA-EXFILTRATION: Exfiltración de Código Fuente, Secretos y Clientes
      const dataExfiltrationPath = this.evaluateDataExfiltration(assetFindings, assetContext);
      if (dataExfiltrationPath) attackPaths.push(dataExfiltrationPath);

      // 5. AP-INFRASTRUCTURE-COMPROMISE: Compromiso de Infraestructura Perimetral / Cloud
      const infraPath = this.evaluateInfrastructureCompromise(assetFindings, assetContext);
      if (infraPath) attackPaths.push(infraPath);

      // 6. AP-SUBDOMAIN-TAKEOVER: Secuestro de Subdominio y Suplantación
      const subdomainTakeoverPath = this.evaluateSubdomainTakeover(assetFindings, assetContext);
      if (subdomainTakeoverPath) attackPaths.push(subdomainTakeoverPath);
    }

    // Ordenar por severidad (CRITICAL primero, luego HIGH, luego MEDIUM)
    const severityWeight: Record<AttackPathSeverity, number> = {
      CRITICAL: 3,
      HIGH: 2,
      MEDIUM: 1,
    };

    return attackPaths.sort((a, b) => severityWeight[b.severity] - severityWeight[a.severity]);
  }

  // --------------------------------------------------------------------------
  // Evaluadores de Rutas de Ataque
  // --------------------------------------------------------------------------

  private evaluatePaymentFraud(
    findings: CorrelatedFinding[],
    assetCtx: { assetId?: string; assetName?: string; assetValue?: string },
  ): AttackPathSummary | null {
    const scriptFindings = findings.filter(
      (f) =>
        f.ruleId === 'WEB-SRI-MISSING-EXTERNAL-SCRIPT' ||
        f.ruleId === 'WEB-EXTERNAL-SCRIPT-UNPINNED',
    );
    const cspFindings = findings.filter(
      (f) => f.ruleId === 'HDR-CSP-MISSING' || f.ruleId === 'HDR-CSP-UNSAFE',
    );
    const formFindings = findings.filter(
      (f) =>
        f.ruleId === 'WEB-FORM-HTTP-TARGET' ||
        f.ruleId === 'HDR-COOKIE-INSECURE' ||
        f.ruleId.includes('COOKIE') ||
        f.location?.includes('checkout') ||
        f.location?.includes('cart'),
    );

    const isTriggered =
      (scriptFindings.length > 0 && cspFindings.length > 0) ||
      (scriptFindings.length > 0 && formFindings.length > 0) ||
      (cspFindings.length > 0 && formFindings.length > 0);

    if (!isTriggered) return null;

    const matchedFindings = [...scriptFindings, ...cspFindings, ...formFindings];
    const enriched = this.mapActiveFindings(matchedFindings);

    const killChainSteps: AttackPathKillChainStep[] = [
      {
        order: 1,
        phase: 'Acceso y Cadena de Suministro',
        title: 'Manipulación de scripts externos sin integridad (SRI)',
        description:
          'El atacante compromete un script o CDN de terceros cargado en la tienda sin hash criptográfico SRI verificado.',
        matched: scriptFindings.length > 0,
        matchedRuleId: scriptFindings[0]?.ruleId,
        findingTitle: scriptFindings[0]?.title,
        location: scriptFindings[0]?.location ?? undefined,
      },
      {
        order: 2,
        phase: 'Inyección en Navegador',
        title: 'Ausencia de directivas CSP estrictas',
        description:
          'La ausencia o laxitud de cabeceras Content-Security-Policy permite ejecutar scripts arbitrarios y abrir conexiones hacia dominios del atacante.',
        matched: cspFindings.length > 0,
        matchedRuleId: cspFindings[0]?.ruleId,
        findingTitle: cspFindings[0]?.title,
        location: cspFindings[0]?.location ?? undefined,
      },
      {
        order: 3,
        phase: 'Exfiltración de Tarjetas (E-Skimming)',
        title: 'Captura no autorizada en flujo de checkout y formularios',
        description:
          'El script malicioso intercepta los datos de tarjetas de crédito y credenciales ingresados en formularios de pago y los envía a servidores de comando y control (Magecart).',
        matched: formFindings.length > 0,
        matchedRuleId: formFindings[0]?.ruleId,
        findingTitle: formFindings[0]?.title,
        location: formFindings[0]?.location ?? undefined,
      },
    ];

    const quickWins = enriched.filter((f) => f.effort === 'QUICK_WIN').length;

    return {
      id: 'AP-PAYMENT-FRAUD',
      title: 'Fraude en Pasarela de Pagos y E-Skimming (Magecart / PCI-DSS v4.0)',
      category: 'PAYMENT_FRAUD',
      severity: 'CRITICAL',
      narrative:
        'Un atacante puede encadenar la falta de integridad en scripts externos con la ausencia de una política CSP estricta para inyectar código malicioso en el navegador del comprador, exfiltrando datos de tarjetas de crédito durante el checkout sin tocar los servidores del comercio.',
      businessRisk:
        'Robo masivo de tarjetas de crédito de clientes, multas graves por incumplimiento de PCI-DSS v4.0 (Req. 6.4.3 / 11.6.1), suspensión de la pasarela de pagos y pérdida de confianza del consumidor.',
      estimatedImpact: 'Crítico — Sanciones de marcas de tarjetas (Visa/Mastercard) de hasta $100,000 USD y litigios de clientes.',
      ...assetCtx,
      killChainSteps,
      activeFindings: enriched,
      quickWinsAvailable: quickWins,
      remediationEffort: quickWins > 0 ? 'QUICK_WIN' : 'MODERATE',
      recommendedActions: [
        'Implementar hashes Subresource Integrity (integrity="sha384-...") en todas las etiquetas <script> externas del checkout.',
        'Activar cabecera Content-Security-Policy restringiendo connect-src y script-src a orígenes verificados.',
        'Asegurar que las cookies de sesión tengan los atributos Secure, HttpOnly y SameSite=Lax/Strict.',
      ],
    };
  }

  private evaluateStoreTakeover(
    findings: CorrelatedFinding[],
    assetCtx: { assetId?: string; assetName?: string; assetValue?: string },
  ): AttackPathSummary | null {
    const loginFindings = findings.filter(
      (f) =>
        f.ruleId === 'PATH-ADMIN-PANEL' ||
        f.ruleId === 'CMS-WP-LOGIN-EXPOSED' ||
        f.ruleId === 'CMS-PRESTASHOP-ADMIN-EXPOSED' ||
        f.ruleId === 'CMS-MAGENTO-ADMIN-EXPOSED' ||
        f.ruleId === 'CMS-SHOPIFY-LOGIN' ||
        f.location?.includes('admin') ||
        f.location?.includes('login'),
    );
    const userEnumFindings = findings.filter(
      (f) => f.ruleId === 'CMS-WP-USER-ENUMERATION',
    );
    const amplificationFindings = findings.filter(
      (f) => f.ruleId === 'CMS-WP-XMLRPC-ENABLED',
    );
    const wafFindings = findings.filter((f) => f.ruleId === 'WAF-MISSING');

    const isTriggered =
      loginFindings.length > 0 &&
      (userEnumFindings.length > 0 || amplificationFindings.length > 0 || wafFindings.length > 0);

    if (!isTriggered) return null;

    const matchedFindings = [
      ...loginFindings,
      ...userEnumFindings,
      ...amplificationFindings,
      ...wafFindings,
    ];
    const enriched = this.mapActiveFindings(matchedFindings);

    const killChainSteps: AttackPathKillChainStep[] = [
      {
        order: 1,
        phase: 'Reconocimiento y Enumeración',
        title: 'Descubrimiento de nombres de usuario válidos en API',
        description:
          'El atacante consulta endpoints como /wp-json/wp/v2/users o canales públicos para recolectar nombres de usuario del equipo de administración.',
        matched: userEnumFindings.length > 0,
        matchedRuleId: userEnumFindings[0]?.ruleId,
        findingTitle: userEnumFindings[0]?.title,
        location: userEnumFindings[0]?.location ?? undefined,
      },
      {
        order: 2,
        phase: 'Vector de Ataque de Acceso',
        title: 'Panel de administración expuesto sin WAF perimetral',
        description:
          'La ruta de administración (wp-login / admin) es directamente accesible desde Internet sin filtrado ni limitación de tasa por WAF.',
        matched: loginFindings.length > 0,
        matchedRuleId: loginFindings[0]?.ruleId,
        findingTitle: loginFindings[0]?.title,
        location: loginFindings[0]?.location ?? undefined,
      },
      {
        order: 3,
        phase: 'Amplificación y Compromiso de Cuenta',
        title: 'Fuerza bruta amplificada vía XML-RPC multicall',
        description:
          'Utilizando xmlrpc.php con system.multicall, el atacante prueba cientos de contraseñas por segundo en una sola petición HTTP hasta obtener acceso como administrador.',
        matched: amplificationFindings.length > 0,
        matchedRuleId: amplificationFindings[0]?.ruleId,
        findingTitle: amplificationFindings[0]?.title,
        location: amplificationFindings[0]?.location ?? undefined,
      },
    ];

    const quickWins = enriched.filter((f) => f.effort === 'QUICK_WIN').length;

    return {
      id: 'AP-STORE-TAKEOVER',
      title: 'Toma de Control de Tienda y Panel de Administración',
      category: 'STORE_TAKEOVER',
      severity: userEnumFindings.length > 0 && amplificationFindings.length > 0 ? 'CRITICAL' : 'HIGH',
      narrative:
        'Un atacante puede recolectar usuarios reales de la tienda online mediante la API REST y ejecutar ataques de fuerza bruta masivos amplificados a través de XML-RPC sin restricción de WAF, logrando acceso completo como administrador del comercio.',
      businessRisk:
        'Secuestro del catálogo de productos, desvío de pagos a cuentas bancarias no autorizadas, acceso a pedidos con información confidencial de compradores y alteración del sitio web.',
      estimatedImpact: 'Alto — Pérdida operativa de la plataforma de ventas y fraude financiero directo.',
      ...assetCtx,
      killChainSteps,
      activeFindings: enriched,
      quickWinsAvailable: quickWins,
      remediationEffort: quickWins > 0 ? 'QUICK_WIN' : 'MODERATE',
      recommendedActions: [
        'Deshabilitar completamente XML-RPC (xmlrpc.php) mediante regla en servidor web o Cloudflare.',
        'Bloquear el acceso no autenticado a /wp-json/wp/v2/users.',
        'Habilitar autenticación multifactor (2FA) obligatoria en el panel administrativo y activar un WAF con rate limiting.',
      ],
    };
  }

  private evaluateBrandImpersonation(
    findings: CorrelatedFinding[],
    assetCtx: { assetId?: string; assetName?: string; assetValue?: string },
  ): AttackPathSummary | null {
    const dmarcFindings = findings.filter(
      (f) =>
        f.ruleId === 'EMAIL-DMARC-MISSING' ||
        f.ruleId === 'EMAIL-DMARC-NONE' ||
        f.ruleId === 'MAIL-DMARC-MISSING' ||
        f.ruleId === 'MAIL-DMARC-MONITOR-ONLY',
    );
    const spfFindings = findings.filter(
      (f) =>
        f.ruleId === 'EMAIL-SPF-MISSING' ||
        f.ruleId === 'EMAIL-SPF-PERMISSIVE-ALL' ||
        f.ruleId === 'MAIL-SPF-MISSING' ||
        f.ruleId === 'MAIL-SPF-PASS-ALL',
    );
    const secondaryFindings = findings.filter(
      (f) =>
        f.ruleId === 'EMAIL-BIMI-INVALID' ||
        f.ruleId === 'EMAIL-IP-BLACKLISTED' ||
        f.ruleId === 'EMAIL-NO-MTA-STS',
    );

    const isTriggered =
      dmarcFindings.length > 0 && (spfFindings.length > 0 || secondaryFindings.length > 0);

    if (!isTriggered) return null;

    const matchedFindings = [...dmarcFindings, ...spfFindings, ...secondaryFindings];
    const enriched = this.mapActiveFindings(matchedFindings);

    const killChainSteps: AttackPathKillChainStep[] = [
      {
        order: 1,
        phase: 'Falsificación de Identidad',
        title: 'Política DMARC permisiva o ausente',
        description:
          'El dominio no exige a los servidores receptores rechazar correos que no provengan de remitentes autorizados (p=none o sin DMARC).',
        matched: dmarcFindings.length > 0,
        matchedRuleId: dmarcFindings[0]?.ruleId,
        findingTitle: dmarcFindings[0]?.title,
        location: dmarcFindings[0]?.location ?? undefined,
      },
      {
        order: 2,
        phase: 'Evasión de Filtros',
        title: 'Permisividad SPF o falta de validación criptográfica',
        description:
          'Los servidores de correo externos aceptan envíos arbitrarios con el dominio del comercio en el encabezado From: sin marcarlos como spam.',
        matched: spfFindings.length > 0,
        matchedRuleId: spfFindings[0]?.ruleId,
        findingTitle: spfFindings[0]?.title,
        location: spfFindings[0]?.location ?? undefined,
      },
      {
        order: 3,
        phase: 'Fraude Comercial (BEC / Phishing)',
        title: 'Envío de facturas fraudulentas o suplantación de cobranza',
        description:
          'El atacante envía correos a clientes o proveedores simulando ser el área contable del comercio, solicitando pagos a cuentas bancarias fraudulentas y afectando la reputación comercial.',
        matched: true,
      },
    ];

    const quickWins = enriched.filter((f) => f.effort === 'QUICK_WIN').length;

    return {
      id: 'AP-BRAND-IMPERSONATION',
      title: 'Suplantación de Marca y Fraude Facturero (BEC / Phishing)',
      category: 'BRAND_IMPERSONATION',
      severity: 'HIGH',
      narrative:
        'Cualquier atacante en Internet puede falsificar el remitente "@dominio.com" del comercio para enviar correos de suplantación creíbles a clientes y proveedores, engañándolos con facturas falsas y cuentas bancarias modificadas.',
      businessRisk:
        'Desvío ilícito de cobros de clientes hacia cuentas de estafadores (Business Email Compromise), pérdida de contratos y degradación de la reputación de marca.',
      estimatedImpact: 'Alto — Pérdida económica de clientes B2B y denuncias por estafa comercial.',
      ...assetCtx,
      killChainSteps,
      activeFindings: enriched,
      quickWinsAvailable: quickWins,
      remediationEffort: 'QUICK_WIN',
      recommendedActions: [
        'Configurar DMARC con política estricta p=quarantine o p=reject (Quick Win de < 20 minutos).',
        'Restringir el registro SPF eliminando el calificador +all o ?all y usando -all restrictivo.',
        'Habilitar DKIM y publicar registro BIMI con logotipo verificado para asegurar la identidad visual en Gmail y Apple Mail.',
      ],
    };
  }

  private evaluateDataExfiltration(
    findings: CorrelatedFinding[],
    assetCtx: { assetId?: string; assetName?: string; assetValue?: string },
  ): AttackPathSummary | null {
    const secretFindings = findings.filter(
      (f) =>
        f.ruleId === 'WEB-SOURCEMAPS-EXPOSED' ||
        f.ruleId === 'WEB-JS-SECRET-EXPOSED' ||
        f.ruleId === 'PATH-ENV-EXPOSED' ||
        f.ruleId === 'PATH-GIT-EXPOSED' ||
        f.ruleId === 'PATH-SECRETS-EXPOSED' ||
        f.ruleId === 'PATH-SQL-DUMP-EXPOSED' ||
        f.ruleId === 'PATH-BACKUP-FILE',
    );
    const apiCorsFindings = findings.filter(
      (f) =>
        f.ruleId === 'WEB-CORS-REFLECTION' ||
        f.ruleId === 'WEB-CORS-WILDCARD-CREDENTIALS' ||
        f.ruleId === 'HDR-CORS-ORIGIN-REFLECTION' ||
        f.ruleId === 'HDR-CORS-WILDCARD' ||
        f.ruleId === 'PATH-SWAGGER-UI-EXPOSED' ||
        f.ruleId === 'PATH-GRAPHQL-INTROSPECTION-EXPOSED',
    );

    const isTriggered =
      secretFindings.length > 0 ||
      (apiCorsFindings.length > 0 && findings.some((f) => f.category === FindingCategory.SENSITIVE_PATH));

    if (!isTriggered) return null;

    const matchedFindings = [...secretFindings, ...apiCorsFindings];
    const enriched = this.mapActiveFindings(matchedFindings);

    const killChainSteps: AttackPathKillChainStep[] = [
      {
        order: 1,
        phase: 'Descubrimiento de Secretos / Código',
        title: 'Exposición de código fuente original o secretos en frontend',
        description:
          'Mapas de código (.js.map), archivos de entorno (.env) o llaves de API expuestas permiten reconstruir la arquitectura y lógica interna del sistema.',
        matched: secretFindings.length > 0,
        matchedRuleId: secretFindings[0]?.ruleId,
        findingTitle: secretFindings[0]?.title,
        location: secretFindings[0]?.location ?? undefined,
      },
      {
        order: 2,
        phase: 'Explotación de APIs y CORS',
        title: 'Reflexión de origen en CORS o endpoints de API documentados',
        description:
          'Configuraciones CORS permisivas o introspección GraphQL/Swagger permiten a sitios externos consultar datos privados con credenciales de usuario.',
        matched: apiCorsFindings.length > 0,
        matchedRuleId: apiCorsFindings[0]?.ruleId,
        findingTitle: apiCorsFindings[0]?.title,
        location: apiCorsFindings[0]?.location ?? undefined,
      },
      {
        order: 3,
        phase: 'Exfiltración de Datos',
        title: 'Extracción de base de datos de usuarios y clientes',
        description:
          'El atacante extrae credenciales de base de datos o consulta APIs autenticadas para volcar registros de clientes, tarjetas y pedidos, con riesgo de venta en mercados clandestinos.',
        matched: true,
      },
    ];

    const quickWins = enriched.filter((f) => f.effort === 'QUICK_WIN').length;

    return {
      id: 'AP-DATA-EXFILTRATION',
      title: 'Exfiltración de Código Fuente, Secretos y Datos de Clientes',
      category: 'DATA_EXFILTRATION',
      severity: 'CRITICAL',
      narrative:
        'La exposición de mapas de código fuente (.js.map) o secretos en archivos públicos permite a terceros reconstruir la aplicación, robar credenciales de base de datos o pasarelas y explotar APIs internas mediante reflexiones CORS indebidas.',
      businessRisk:
        'Filtración masiva de bases de datos de clientes (RGPD / Habeas Data), robo de propiedad intelectual del software comercial y multas de entes regulatorios.',
      estimatedImpact: 'Crítico — Demandas legales, multas regulatorias y daño severo a la credibilidad del comercio.',
      ...assetCtx,
      killChainSteps,
      activeFindings: enriched,
      quickWinsAvailable: quickWins,
      remediationEffort: quickWins > 0 ? 'QUICK_WIN' : 'MODERATE',
      recommendedActions: [
        'Desactivar la generación o publicación de archivos .js.map en entornos de producción.',
        'Eliminar de inmediato archivos .env, .git o copias de seguridad del directorio raíz del servidor web.',
        'Restringir la política de orígenes permitidos en CORS evitando el reflejo ciego del encabezado Origin.',
      ],
    };
  }

  private evaluateInfrastructureCompromise(
    findings: CorrelatedFinding[],
    assetCtx: { assetId?: string; assetName?: string; assetValue?: string },
  ): AttackPathSummary | null {
    const portFindings = findings.filter(
      (f) =>
        f.ruleId === 'PORT-EXPOSED-DATABASE' ||
        f.ruleId === 'PORT-EXPOSED-SSH' ||
        f.ruleId === 'PORT-EXPOSED-RDP' ||
        f.ruleId === 'SVC-CLEARTEXT-REMOTE-ADMIN' ||
        f.ruleId === 'SVC-CLEARTEXT-FILE-TRANSFER' ||
        f.ruleId === 'SVC-DATABASE-EXPOSED' ||
        f.ruleId === 'SVC-ORCHESTRATION-EXPOSED',
    );
    const vulnFindings = findings.filter(
      (f) =>
        f.ruleId === 'CVE-EXPLOITED-KEV' ||
        f.ruleId === 'CVE-HIGH-EPSS' ||
        f.ruleId.startsWith('CSPM-') ||
        f.ruleId.includes('PUBLIC-READ') ||
        f.ruleId.includes('PUBLIC-ACCESS'),
    );

    const isTriggered = portFindings.length > 0 || vulnFindings.length > 0;
    if (!isTriggered) return null;

    const matchedFindings = [...portFindings, ...vulnFindings];
    const enriched = this.mapActiveFindings(matchedFindings);

    const killChainSteps: AttackPathKillChainStep[] = [
      {
        order: 1,
        phase: 'Exposición Perimetral',
        title: 'Servicios de gestión o bases de datos expuestos a Internet',
        description:
          'Puertos de administración (SSH, RDP, Telnet) o motores de base de datos son directamente accesibles sin túnel VPN.',
        matched: portFindings.length > 0,
        matchedRuleId: portFindings[0]?.ruleId,
        findingTitle: portFindings[0]?.title,
        location: portFindings[0]?.location ?? undefined,
      },
      {
        order: 2,
        phase: 'Explotación / Acceso Inicial',
        title: 'Vulnerabilidades con exploit público (CISA KEV) o buckets abiertos',
        description:
          'El atacante utiliza herramientas automatizadas para explotar fallos conocidos o acceder a almacenamiento en la nube sin autenticación.',
        matched: vulnFindings.length > 0,
        matchedRuleId: vulnFindings[0]?.ruleId,
        findingTitle: vulnFindings[0]?.title,
        location: vulnFindings[0]?.location ?? undefined,
      },
      {
        order: 3,
        phase: 'Impacto en Infraestructura',
        title: 'Ransomware y compromiso integral del servidor',
        description:
          'Acceso con privilegios de root/administrador, movimiento lateral y cifrado extorsivo de discos y respaldos, provocando la paralización completa de operaciones.',
        matched: true,
      },
    ];

    const quickWins = enriched.filter((f) => f.effort === 'QUICK_WIN').length;

    return {
      id: 'AP-INFRASTRUCTURE-COMPROMISE',
      title: 'Compromiso de Infraestructura Perimetral y Recursos Cloud',
      category: 'INFRASTRUCTURE_COMPROMISE',
      severity: 'CRITICAL',
      narrative:
        'Servicios de gestión interna o motores de base de datos expuestos directamente a Internet permiten ataques de fuerza bruta automatizados o explotación de vulnerabilidades conocidas para acceder al servidor interno.',
      businessRisk:
        'Infección por ransomware, secuestro y cifrado de bases de datos operativas y pérdida irrecuperable de información transaccional.',
      estimatedImpact: 'Crítico — Interrupción total del negocio y posibles demandas por rescate de datos.',
      ...assetCtx,
      killChainSteps,
      activeFindings: enriched,
      quickWinsAvailable: quickWins,
      remediationEffort: 'QUICK_WIN',
      recommendedActions: [
        'Cerrar en firewall / Security Groups el acceso público a puertos de bases de datos y administración remota (Quick Win de < 15 min).',
        'Exigir acceso exclusivamente a través de VPN corporativa o Bastion Host con autenticación multifactor.',
        'Actualizar con urgencia servicios con CVEs activos en el catálogo CISA KEV.',
      ],
    };
  }

  private evaluateSubdomainTakeover(
    findings: CorrelatedFinding[],
    assetCtx: { assetId?: string; assetName?: string; assetValue?: string },
  ): AttackPathSummary | null {
    const takeoverFindings = findings.filter(
      (f) =>
        f.ruleId === 'SUBDOMAIN-TAKEOVER-RISK' ||
        f.ruleId === 'DNS-DNSSEC-BOGUS',
    );

    if (takeoverFindings.length === 0) return null;

    const enriched = this.mapActiveFindings(takeoverFindings);

    const killChainSteps: AttackPathKillChainStep[] = [
      {
        order: 1,
        phase: 'Detección de Alias Huérfano',
        title: 'Registro CNAME apuntando a recurso en la nube no reclamado',
        description:
          'Un subdominio corporativo apunta hacia un servicio en la nube (S3, GitHub Pages, Azure App, etc.) cuyo recurso fue eliminado pero el registro DNS no se borró.',
        matched: true,
        matchedRuleId: takeoverFindings[0]?.ruleId,
        findingTitle: takeoverFindings[0]?.title,
        location: takeoverFindings[0]?.location ?? undefined,
      },
      {
        order: 2,
        phase: 'Adquisición Hostile',
        title: 'Reclamación del recurso por parte del atacante',
        description:
          'El atacante crea una cuenta en el proveedor de nube y reclama el identificador huérfano para hospedar una tienda clonada con certificado SSL válido y legítimo del dominio.',
        matched: true,
      },
      {
        order: 3,
        phase: 'Suplantación de Marca y Robo',
        title: 'Captura de credenciales y desvío de clientes',
        description:
          'Los clientes confían en la URL oficial del comercio y entregan sus credenciales o realizan compras en la tienda falsa del atacante bajo la reputación directa de la marca.',
        matched: true,
      },
    ];

    const quickWins = enriched.filter((f) => f.effort === 'QUICK_WIN').length;

    return {
      id: 'AP-SUBDOMAIN-TAKEOVER',
      title: 'Secuestro de Subdominio y Suplantación de Tienda (Subdomain Takeover)',
      category: 'SUBDOMAIN_TAKEOVER',
      severity: 'HIGH',
      narrative:
        'Un subdominio legítimo del comercio apunta mediante CNAME a un recurso externo inexistente. Cualquier atacante puede registrar dicho recurso en el proveedor de nube para hospedar una tienda falsa con certificado válido.',
      businessRisk:
        'Suplantación indetectable de la tienda corporativa, captura de credenciales y robo de cookies de sesión con alcance general de dominio.',
      estimatedImpact: 'Alto — Fraude masivo a clientes operando bajo un subdominio verificado de la empresa.',
      ...assetCtx,
      killChainSteps,
      activeFindings: enriched,
      quickWinsAvailable: quickWins,
      remediationEffort: 'QUICK_WIN',
      recommendedActions: [
        'Eliminar de inmediato el registro CNAME huérfano en la zona DNS del proveedor (Quick Win de < 15 min).',
        'Verificar los endpoints externos en la nube para asegurar que todos los recursos sigan activos y bajo control de la empresa.',
      ],
    };
  }

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  private mapActiveFindings(findings: CorrelatedFinding[]) {
    // Deduplicar por id
    const unique = new Map<string, CorrelatedFinding>();
    for (const f of findings) {
      unique.set(f.id, f);
    }

    return Array.from(unique.values()).map((f) => {
      const rule = FINDING_RULES.get(f.ruleId);
      return {
        id: f.id,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        location: f.location ?? undefined,
        effort: rule?.effort ?? 'MODERATE',
        estimatedMinutes: rule?.estimatedMinutes ?? 60,
      };
    });
  }
}
