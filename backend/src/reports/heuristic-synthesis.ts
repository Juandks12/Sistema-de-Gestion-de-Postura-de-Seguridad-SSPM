import { FindingSeverity } from '@prisma/client';
import {
  BusinessImpact,
  ExecutiveBusinessSummary,
  StrategicPriority,
} from './executive-summary.interface';
import { ReportData, prioritizedFindings } from './report-data';

/**
 * Motor de síntesis experta: analiza hallazgos, puertos, EOL y tendencias
 * para generar diagnósticos en lenguaje de negocio e impactos empresariales
 * de forma determinista y de alta precisión (sin requerir LLM externo).
 */
export function generateHeuristicSummary(data: ReportData): ExecutiveBusinessSummary {
  const s = data.score;
  const isAsset = data.scope.kind === 'ASSET';
  const subject =
    data.scope.kind === 'ASSET'
      ? data.scope.name
        ? `${data.scope.name} (${data.scope.value})`
        : data.scope.value
      : data.organizationName;

  // 1. Nivel de riesgo
  let riskLevel: 'CRÍTICO' | 'ALTO' | 'MODERADO' | 'BAJO' = 'BAJO';
  if (s.counts.CRITICAL > 0 || (s.score !== null && s.score < 50)) {
    riskLevel = 'CRÍTICO';
  } else if (s.counts.HIGH > 0 || (s.score !== null && s.score < 70)) {
    riskLevel = 'ALTO';
  } else if (s.counts.MEDIUM > 0 || (s.score !== null && s.score < 85)) {
    riskLevel = 'MODERADO';
  }

  // 2. Tendencia del score
  let trendLabel = 'Estable';
  if (s.score === null) {
    trendLabel = 'Sin evaluación suficiente';
  } else if (s.weekAgoScore === null) {
    trendLabel = 'Línea base inicial';
  } else {
    const delta = s.score - s.weekAgoScore;
    if (delta <= -10) {
      trendLabel = `En deterioro significativo (-${Math.abs(delta)} pts en 7 días)`;
    } else if (delta < 0) {
      trendLabel = `Leve retroceso (-${Math.abs(delta)} pts)`;
    } else if (delta > 0) {
      trendLabel = `En mejora (+${delta} pts)`;
    }
  }

  // 3. Titular diagnóstico
  let headline: string;
  if (riskLevel === 'CRÍTICO') {
    headline = `Postura crítica en ${subject}: vulnerabilidades severas o exposición directa de servicios centrales`;
  } else if (riskLevel === 'ALTO') {
    headline = `Postura comprometida en ${subject}: riesgos de alta severidad que requieren mitigación a corto plazo`;
  } else if (riskLevel === 'MODERADO') {
    headline = `Postura moderada en ${subject}: superficie bajo control con áreas puntuales de endurecimiento`;
  } else {
    headline = `Postura sólida y bajo nivel de riesgo perimetral en ${subject}`;
  }

  // 4. Hallazgos abiertos y puertos
  const findings = prioritizedFindings(data);
  const criticalOrHigh = findings.filter(
    (f) => f.severity === FindingSeverity.CRITICAL || f.severity === FindingSeverity.HIGH,
  );
  const allOpenPorts = data.assets.flatMap((a) => a.openPorts);

  const hasDbPorts = allOpenPorts.some((p) => [3306, 5432, 27017, 6379, 1433, 9200].includes(p.port));
  const hasAdminExposed = findings.some(
    (f) => f.ruleId === 'API-ACTUATOR-ENV-EXPOSED' || f.ruleId === 'PATH-ADMIN-PANEL',
  );
  const hasKevVuln = findings.some((f) => (f.evidence as Record<string, unknown> | null)?.kev === true);
  const hasEolTech = findings.some((f) => f.ruleId === 'HDR-EOL-TECH');
  const hasEmailRisk = findings.some((f) => f.ruleId.startsWith('EMAIL-') || f.ruleId.startsWith('DNS-'));
  const hasSslRisk = findings.some((f) => f.ruleId.startsWith('SSL-'));

  // 5. Visión General Ejecutiva (Lenguaje de negocio)
  let executiveOverview: string;
  if (s.score === null) {
    executiveOverview =
      `La entidad ${subject} se encuentra en fase inicial de auditoría. Se requiere ejecutar escaneos perimetrales ` +
      'completos sobre sus activos para establecer la primera medición cuantitativa de riesgo.';
  } else {
    executiveOverview =
      `La postura perimetral de ${subject} registra una calificación de ${s.score}/100 (Grado ${s.grade}, Nivel ${s.label.toLowerCase()}). ` +
      (criticalOrHigh.length > 0
        ? `Se identifican ${criticalOrHigh.length} exposiciones de atención urgente que representan vectores inmediatos para actores maliciosos. `
        : 'No se detectan fallas críticas directas en la superficie externa expuesta. ') +
      (hasDbPorts
        ? 'Preocupa especialmente la detección de puertos de bases de datos o almacenamiento accesibles desde internet. '
        : '') +
      (hasKevVuln
        ? 'Existen vulnerabilidades con registro de explotación activa en el catálogo oficial CISA KEV. '
        : '') +
      (hasEolTech
        ? 'Se evidencia deuda técnica por componentes de software que han alcanzado su Fin de Ciclo de Vida (EOL). '
        : '') +
      `La tendencia general se califica como ${trendLabel.toLowerCase()}.`;
  }

  // 6. Impactos en el Negocio (4 áreas)
  const businessImpacts: BusinessImpact[] = [
    {
      area: 'Operativa',
      severity: hasDbPorts || hasKevVuln ? 'CRÍTICO' : criticalOrHigh.length > 0 ? 'ALTO' : 'BAJO',
      description: hasDbPorts
        ? 'Riesgo crítico de secuestro de servidores, ransomware o indisponibilidad por acceso directo a bases de datos expuestas.'
        : hasKevVuln
          ? 'Potencial interrupción súbita de operaciones mediante explotación remota de vulnerabilidades sin parchear.'
          : hasSslRisk
            ? 'Posible bloqueo de clientes y proveedores debido a certificados TLS expirados o navegación insegura.'
            : 'Continuidad operativa preservada; bajo riesgo de interrupción perimetral no planificada.',
    },
    {
      area: 'Financiera',
      severity: hasAdminExposed || hasDbPorts ? 'CRÍTICO' : criticalOrHigh.length > 0 ? 'ALTO' : 'BAJO',
      description: hasAdminExposed
        ? 'Pérdida financiera significativa derivada de exfiltración de credenciales en endpoints de telemetría y abuso de servicios en la nube.'
        : hasDbPorts
          ? 'Costos severos de remediación, respuesta a incidentes forenses y potencial extorsión por robo de datos.'
          : criticalOrHigh.length > 0
            ? 'Costos imprevistos de atención reactiva de seguridad y degradación en transacciones comerciales.'
            : 'Impacto financiero mínimo bajo las condiciones actuales de exposición.',
    },
    {
      area: 'Regulatoria/Legal',
      severity: hasDbPorts || hasAdminExposed ? 'ALTO' : criticalOrHigh.length > 0 || hasEolTech ? 'MEDIO' : 'BAJO',
      description: hasDbPorts || hasAdminExposed
        ? 'Incumplimiento de estándares de custodia de información y normativas de protección de datos personales (Habeas Data / RGPD), con exposición a sanciones legales.'
        : hasEolTech
          ? 'No conformidad con auditorías de cumplimiento que prohíben el uso de componentes de software en Fin de Vida Útil (EOL).'
          : 'Postura alineada con requerimientos perimetrales y principios de debida diligencia.',
    },
    {
      area: 'Reputacional',
      severity: hasEmailRisk ? 'ALTO' : hasAdminExposed ? 'MEDIO' : 'BAJO',
      description: hasEmailRisk
        ? 'Riesgo de fraude y suplantación de identidad (phishing/BEC) a clientes y socios comerciales usando el dominio de la empresa.'
        : criticalOrHigh.length > 0
          ? 'Visibilidad pública de fallas de seguridad que puede debilitar la confianza de clientes y socios corporativos.'
          : 'Confianza de marca y credibilidad corporativa debidamente resguardadas.',
    },
  ];

  // 7. Top 3 Acciones Prioritarias Estratégicas
  const topPriorities: StrategicPriority[] = [];
  let priorityOrder = 1;

  if (hasDbPorts || hasAdminExposed) {
    topPriorities.push({
      order: priorityOrder++,
      title: 'Aislamiento Perimetral Inmediato',
      action: 'Bloquear mediante firewall el acceso público a puertos de bases de datos y endpoints administrativos (/actuator, /env).',
      businessJustification: 'Elimina de raíz los vectores de intrusión directa más destructivos sin requerir modificaciones en el código de las aplicaciones.',
      affectedTarget: hasDbPorts ? 'Bases de datos y servicios internos' : 'Endpoints de administración y configuración',
    });
  }

  if (hasKevVuln || criticalOrHigh.some((f) => f.ruleId === 'VULN-KNOWN-CVE')) {
    topPriorities.push({
      order: priorityOrder++,
      title: 'Plan de Parcheo de Vulnerabilidades Críticas',
      action: 'Aplicar actualizaciones de seguridad en los servicios con CVEs activos o restringir su exposición pública mediante WAF/VPN.',
      businessJustification: 'Cierra brechas que cuentan con herramientas automatizadas de ataque y explotación activa en internet.',
      affectedTarget: 'Servicios web y componentes con CVEs reportados',
    });
  }

  if (hasEmailRisk) {
    topPriorities.push({
      order: priorityOrder++,
      title: 'Blindaje de Identidad de Correo y Dominio',
      action: 'Configurar registros SPF, DKIM y establecer una política DMARC estricta (p=reject o p=quarantine).',
      businessJustification: 'Evita que terceros envíen correos fraudulentos en nombre de la empresa a clientes y proveedores.',
      affectedTarget: isAsset ? subject : 'Dominio corporativo y registros DNS',
    });
  } else if (hasEolTech || findings.length > 0) {
    topPriorities.push({
      order: priorityOrder++,
      title: 'Actualización y Endurecimiento de Cabeceras HTTP',
      action: 'Configurar cabeceras de seguridad (HSTS, CSP, X-Frame-Options) y planificar migración de software EOL.',
      businessJustification: 'Mitiga ataques hacia usuarios finales y reduce la deuda técnica perimetral acumulada.',
      affectedTarget: 'Servidores web y aplicaciones expuestas',
    });
  }

  if (topPriorities.length < 3) {
    topPriorities.push({
      order: priorityOrder++,
      title: 'Mantenimiento del Monitoreo Continuo',
      action: 'Mantener activos los escaneos automatizados periódicos y verificar la resolución de alertas en menos de 24 horas.',
      businessJustification: 'Garantiza detección temprana ante nuevas exposiciones o cambios no autorizados en la infraestructura.',
      affectedTarget: 'Infraestructura completa monitoreada',
    });
  }

  // 8. Resumen de Deuda Técnica
  let technicalDebtSummary: string | undefined;
  if (hasEolTech || hasSslRisk || hasDbPorts) {
    const debtPoints: string[] = [];
    if (hasEolTech) debtPoints.push('Software en fin de ciclo de soporte (EOL) sin parches del fabricante');
    if (hasSslRisk) debtPoints.push('Certificados TLS o configuraciones criptográficas obsoletas');
    if (hasDbPorts) debtPoints.push('Servicios internos expuestos sin túneles VPN ni listas blancas');
    technicalDebtSummary = `Factores de deuda técnica identificados: ${debtPoints.join('; ')}. Se sugiere incluir su resolución en el presupuesto y backlog operativo.`;
  }

  return {
    headline,
    riskLevel,
    scoreOverview: {
      score: s.score,
      grade: s.grade,
      trendLabel,
    },
    executiveOverview,
    businessImpacts,
    topPriorities: topPriorities.slice(0, 3),
    technicalDebtSummary,
    generatedAt: new Date().toISOString(),
    provider: 'heuristic-expert',
  };
}
