import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { EmbeddingService } from '../embeddings/embedding.service';
import { COMPLIANCE_CONTROLS } from '../../compliance/compliance.catalog';
import { HARDENING_GUIDES } from './hardening-iac.catalog';

export interface IngestionStats {
  total: number;
  byCategory: {
    CVE: number;
    GRC_CONTROL: number;
    HARDENING_GUIDE: number;
    REMEDIATION_IAC: number;
  };
  lastSyncedAt: Date | null;
}

export const SEED_CRITICAL_KEV_ENTRIES = [
  {
    cveId: 'CVE-2024-6387',
    vulnerabilityName: 'OpenSSH Server Remote Code Execution (regreSSHion)',
    vendor: 'OpenSSH',
    product: 'sshd',
    shortDescription: 'Condición de carrera de señal en el demonio OpenSSH (sshd) que permite a un atacante no autenticado ejecutar código arbitrario con privilegios de root.',
    requiredAction: 'Actualizar OpenSSH a versión 9.8p1 o superior; mitigar estableciendo LoginGraceTime 0 en sshd_config.',
    knownRansomwareCampaignUse: 'Known',
  },
  {
    cveId: 'CVE-2021-44228',
    vulnerabilityName: 'Apache Log4j2 JNDI Remote Code Execution (Log4Shell)',
    vendor: 'Apache',
    product: 'Log4j',
    shortDescription: 'Inyección JNDI en mensajes de log de Apache Log4j2 que permite a un atacante no autenticado ejecutar código arbitrario remoto al registrar una cadena maliciosa.',
    requiredAction: 'Actualizar Log4j a 2.17.1 o superior, o deshabilitar la búsqueda de mensajes estableciendo log4j2.formatMsgNoLookups=true.',
    knownRansomwareCampaignUse: 'Known',
  },
  {
    cveId: 'CVE-2023-34362',
    vulnerabilityName: 'Progress MOVEit Transfer SQL Injection Vulnerability',
    vendor: 'Progress Software',
    product: 'MOVEit Transfer',
    shortDescription: 'Inyección SQL en la aplicación web MOVEit Transfer que permite a un atacante no autenticado acceder a la base de datos subyacente y exfiltrar información sensible.',
    requiredAction: 'Aplicar los parches de seguridad del fabricante y deshabilitar acceso HTTP/HTTPS público al puerto de administración web.',
    knownRansomwareCampaignUse: 'Known',
  },
  {
    cveId: 'CVE-2023-4966',
    vulnerabilityName: 'Citrix NetScaler ADC & Gateway Sensitive Information Disclosure (Citrix Bleed)',
    vendor: 'Citrix',
    product: 'NetScaler ADC / Gateway',
    shortDescription: 'Desbordamiento de búfer en NetScaler ADC y Gateway que permite a un atacante remoto no autenticado extraer memoria del proceso, incluyendo tokens de sesión de autenticación multifactor.',
    requiredAction: 'Actualizar firmware a las versiones corregidas y revocar todas las sesiones y tokens de sesión activos de los usuarios.',
    knownRansomwareCampaignUse: 'Known',
  },
  {
    cveId: 'CVE-2024-21762',
    vulnerabilityName: 'Fortinet FortiOS Out-of-bounds Write in SSL-VPN',
    vendor: 'Fortinet',
    product: 'FortiOS',
    shortDescription: 'Escritura fuera de límites en el componente SSL-VPN de FortiOS que permite a un atacante remoto no autenticado ejecutar código o comandos no autorizados mediante solicitudes HTTP especialmente diseñadas.',
    requiredAction: 'Actualizar a FortiOS 7.4.3, 7.2.7 o superior, o deshabilitar el portal web SSL-VPN si no es indispensable.',
    knownRansomwareCampaignUse: 'Known',
  },
  {
    cveId: 'CVE-2021-41773',
    vulnerabilityName: 'Apache HTTP Server Path Traversal and File Disclosure',
    vendor: 'Apache',
    product: 'HTTP Server',
    shortDescription: 'Salto de directorio (path traversal) y ejecución remota de código en Apache HTTP Server 2.4.49 y 2.4.50 al procesar URLs con caracteres codificados.',
    requiredAction: 'Actualizar Apache HTTP Server a versión 2.4.51 o superior.',
    knownRansomwareCampaignUse: 'Known',
  },
  {
    cveId: 'CVE-2022-22965',
    vulnerabilityName: 'Spring Framework Remote Code Execution (Spring4Shell)',
    vendor: 'VMware',
    product: 'Spring Framework',
    shortDescription: 'Vulnerabilidad de enlace de datos en Spring Framework MVC y Spring WebFlux en JDK 9+ que permite a atacantes remotos escribir archivos JSP maliciosos y lograr RCE.',
    requiredAction: 'Actualizar a Spring Framework 5.3.18, 5.2.20 o superior.',
    knownRansomwareCampaignUse: 'Known',
  },
];

@Injectable()
export class KnowledgeIngestionService implements OnApplicationBootstrap {
  private readonly logger = new Logger(KnowledgeIngestionService.name);
  private isIngesting = false;
  private lastSyncedAt: Date | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly embeddingService: EmbeddingService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    // Sincroniza la base de conocimiento en segundo plano al arrancar la aplicación
    this.syncKnowledgeBase().catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Error durante la sincronización inicial de RAG: ${msg}`);
    });
  }

  async syncKnowledgeBase(): Promise<IngestionStats> {
    if (this.isIngesting) {
      this.logger.log('Sincronización de base de conocimiento RAG ya en progreso...');
      return this.getStats();
    }

    this.isIngesting = true;
    this.logger.log('Iniciando sincronización e ingesta de Base de Conocimiento RAG de Ciberseguridad...');

    try {
      // 1. Ingesta de Controles GRC
      await this.ingestGrcControls();

      // 2. Ingesta de Guías de Hardening
      await this.ingestHardeningGuides();

      // 3. Ingesta de Snippets de Remediación IaC
      await this.ingestRemediationIac();

      // 4. Ingesta de CISA KEV
      await this.ingestCisaKev();

      this.lastSyncedAt = new Date();
      this.logger.log('Sincronización de Base de Conocimiento RAG completada con éxito.');
    } finally {
      this.isIngesting = false;
    }

    return this.getStats();
  }

  async getStats(): Promise<IngestionStats> {
    const counts = (await this.prisma.$queryRaw`
      SELECT category, COUNT(*)::int AS count 
      FROM knowledge_embeddings 
      GROUP BY category
    `) as Array<{ category: string; count: number }>;

    const byCat = {
      CVE: 0,
      GRC_CONTROL: 0,
      HARDENING_GUIDE: 0,
      REMEDIATION_IAC: 0,
    };

    let total = 0;
    for (const c of counts) {
      const cat = c.category as keyof typeof byCat;
      if (byCat[cat] !== undefined) {
        byCat[cat] = c.count;
        total += c.count;
      }
    }

    return {
      total,
      byCategory: byCat,
      lastSyncedAt: this.lastSyncedAt,
    };
  }

  private async ingestGrcControls(): Promise<void> {
    for (const ctrl of COMPLIANCE_CONTROLS) {
      const sourceId = `GRC-${ctrl.framework}-${ctrl.code}`;
      const exists = await this.recordExists(sourceId);
      if (exists) continue;

      const title = `[${ctrl.framework}] Control ${ctrl.code}: ${ctrl.title}`;
      const content = `Marco de Cumplimiento: ${ctrl.framework}
Dominio: ${ctrl.domain}
Código: ${ctrl.code}
Título: ${ctrl.title}
Descripción Técnica: ${ctrl.description}
Reglas Técnicas SSPM Asociadas: ${ctrl.ruleIds.join(', ')}`;

      const metadata = {
        framework: ctrl.framework,
        code: ctrl.code,
        domain: ctrl.domain,
        rules: ctrl.ruleIds,
      };

      await this.saveEmbedding('GRC_CONTROL', sourceId, title, content, metadata);
    }
  }

  private async ingestHardeningGuides(): Promise<void> {
    for (const guide of HARDENING_GUIDES) {
      const sourceId = guide.sourceId;
      const exists = await this.recordExists(sourceId);
      if (exists) continue;

      const title = `[Hardening] ${guide.title} (${guide.technology})`;
      const content = `Tecnología: ${guide.technology}
Título: ${guide.title}
Directrices de Bastionado:
${guide.content}
Referencias: ${guide.references.join(', ')}`;

      const metadata = {
        technology: guide.technology,
        references: guide.references,
      };

      await this.saveEmbedding('HARDENING_GUIDE', sourceId, title, content, metadata);
    }
  }

  private async ingestRemediationIac(): Promise<void> {
    for (const guide of HARDENING_GUIDES) {
      if (!guide.remediationIac) continue;
      const sourceId = `IAC-${guide.sourceId}`;
      const exists = await this.recordExists(sourceId);
      if (exists) continue;

      const title = `[IaC Remediation] ${guide.remediationIac.description} (${guide.remediationIac.format})`;
      const content = `Tecnología: ${guide.technology}
Formato de Remediación: ${guide.remediationIac.format}
Descripción: ${guide.remediationIac.description}
Código de Configuración / Script de Remediación:
\`\`\`${guide.remediationIac.format}
${guide.remediationIac.code}
\`\`\``;

      const metadata = {
        format: guide.remediationIac.format,
        guideId: guide.sourceId,
        technology: guide.technology,
      };

      await this.saveEmbedding('REMEDIATION_IAC', sourceId, title, content, metadata);
    }
  }

  private async ingestCisaKev(): Promise<void> {
    for (const entry of SEED_CRITICAL_KEV_ENTRIES) {
      const sourceId = entry.cveId;
      const exists = await this.recordExists(sourceId);
      if (exists) continue;

      const title = `[CISA KEV] ${entry.cveId} - ${entry.vulnerabilityName}`;
      const content = `CVE ID: ${entry.cveId}
Vulnerabilidad: ${entry.vulnerabilityName}
Fabricante / Proyecto: ${entry.vendor}
Producto Afectado: ${entry.product}
Uso en Campañas de Ransomware: ${entry.knownRansomwareCampaignUse}
Descripción: ${entry.shortDescription}
Acción de Remediación Obligatoria CISA: ${entry.requiredAction}`;

      const metadata = {
        cveId: entry.cveId,
        vendor: entry.vendor,
        product: entry.product,
        ransomware: entry.knownRansomwareCampaignUse,
      };

      await this.saveEmbedding('CVE', sourceId, title, content, metadata);
    }
  }

  private async recordExists(sourceId: string): Promise<boolean> {
    const existing = (await this.prisma.$queryRaw`
      SELECT id FROM knowledge_embeddings WHERE source_id = ${sourceId} LIMIT 1
    `) as Array<{ id: string }>;
    return existing.length > 0;
  }

  private async saveEmbedding(
    category: 'CVE' | 'GRC_CONTROL' | 'HARDENING_GUIDE' | 'REMEDIATION_IAC',
    sourceId: string,
    title: string,
    content: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    const embedding = await this.embeddingService.generateEmbedding(`${title}\n${content}`);
    const vectorString = `[${embedding.join(',')}]`;

    await this.prisma.$executeRawUnsafe(
      `INSERT INTO knowledge_embeddings 
        (id, category, source_id, title, content, metadata, embedding, created_at, updated_at) 
       VALUES 
        (gen_random_uuid(), $1::"KnowledgeCategory", $2, $3, $4, $5::jsonb, $6::vector, NOW(), NOW())
       ON CONFLICT (id) DO NOTHING`,
      category,
      sourceId,
      title,
      content,
      JSON.stringify(metadata),
      vectorString,
    );
  }
}
