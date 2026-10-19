export enum ComplianceFramework {
  ISO_27001 = 'ISO_27001',
  PCI_DSS = 'PCI_DSS',
  SOC_2 = 'SOC_2',
  NIST_CSF = 'NIST_CSF',
  CIS_CONTROLS = 'CIS_CONTROLS',
}

export interface ComplianceControlDefinition {
  id: string;
  framework: ComplianceFramework;
  code: string;
  title: string;
  domain: string;
  description: string;
  ruleIds: string[];
}

export interface FrameworkMetadata {
  id: ComplianceFramework;
  name: string;
  version: string;
  description: string;
  iconName: string;
}

export const FRAMEWORKS_METADATA: Record<ComplianceFramework, FrameworkMetadata> = {
  [ComplianceFramework.ISO_27001]: {
    id: ComplianceFramework.ISO_27001,
    name: 'ISO/IEC 27001:2022',
    version: '2022 (Anexo A)',
    description: 'Estándar internacional para Sistemas de Gestión de Seguridad de la Información (SGSI).',
    iconName: 'ShieldCheck',
  },
  [ComplianceFramework.PCI_DSS]: {
    id: ComplianceFramework.PCI_DSS,
    name: 'PCI-DSS v4.0',
    version: '4.0',
    description: 'Estándar de seguridad de datos para la industria de tarjetas de pago y entornos transaccionales.',
    iconName: 'CreditCard',
  },
  [ComplianceFramework.SOC_2]: {
    id: ComplianceFramework.SOC_2,
    name: 'SOC 2 Type II',
    version: '2022 TSC',
    description: 'Criterios de servicios de confianza (Seguridad, Disponibilidad y Confidencialidad) de AICPA.',
    iconName: 'Lock',
  },
  [ComplianceFramework.NIST_CSF]: {
    id: ComplianceFramework.NIST_CSF,
    name: 'NIST CSF 2.0',
    version: '2.0',
    description: 'Marco de Ciberseguridad del Instituto Nacional de Estándares y Tecnología.',
    iconName: 'Award',
  },
  [ComplianceFramework.CIS_CONTROLS]: {
    id: ComplianceFramework.CIS_CONTROLS,
    name: 'CIS Controls v8',
    version: 'v8 (IG1 / IG2)',
    description: 'Conjunto priorizado de mejores prácticas defensivas contra ciberamenazas habituales.',
    iconName: 'CheckCircle2',
  },
};

export const COMPLIANCE_CONTROLS: ComplianceControlDefinition[] = [
  // =========================================================================
  // ISO/IEC 27001:2022 (Anexo A)
  // =========================================================================
  {
    id: 'ISO-A.8.20',
    framework: ComplianceFramework.ISO_27001,
    code: 'A.8.20',
    title: 'Seguridad en Redes y Conexiones',
    domain: 'Seguridad Tecnológica',
    description:
      'Las redes y los dispositivos de red deben ser protegidos, gestionados y controlados para salvaguardar la información en los sistemas y aplicaciones.',
    ruleIds: [
      'MAIL-SPF-MISSING',
      'MAIL-SPF-INVALID',
      'MAIL-SPF-PASS-ALL',
      'MAIL-DMARC-MISSING',
      'MAIL-DMARC-INVALID',
      'MAIL-DKIM-NOT-FOUND',
      'DNS-NO-CAA',
      'DNS-NO-DNSSEC',
      'DNS-DNSSEC-BOGUS',
      'EMAIL-NO-MTA-STS',
      'EMAIL-IP-BLACKLISTED',
    ],
  },
  {
    id: 'ISO-A.8.24',
    framework: ComplianceFramework.ISO_27001,
    code: 'A.8.24',
    title: 'Uso de la Criptografía y Cifrado en Tránsito',
    domain: 'Seguridad Tecnológica',
    description:
      'Se deben definir y aplicar reglas para el uso eficaz de la criptografía, garantizando la confidencialidad e integridad de las comunicaciones.',
    ruleIds: [
      'TLS-EXPIRED',
      'TLS-EXPIRING-7D',
      'TLS-EXPIRING-30D',
      'TLS-NOT-YET-VALID',
      'TLS-HOSTNAME-MISMATCH',
      'TLS-UNTRUSTED-CHAIN',
      'TLS-LEGACY-PROTOCOL',
      'TLS-WEAK-KEY',
      'TLS-WEAK-SIGNATURE',
      'TLS-NOT-AVAILABLE',
      'HDR-HSTS-MISSING',
      'HDR-HSTS-SHORT',
      'HDR-HTTP-NO-REDIRECT',
      'SVC-CLEARTEXT-REMOTE-ADMIN',
      'SVC-CLEARTEXT-FILE-TRANSFER',
      'SVC-MAIL-CLEARTEXT',
    ],
  },
  {
    id: 'ISO-A.8.26',
    framework: ComplianceFramework.ISO_27001,
    code: 'A.8.26',
    title: 'Requisitos de Seguridad en Aplicaciones Web',
    domain: 'Seguridad de Aplicaciones',
    description:
      'Los requisitos de seguridad de la información deben identificarse, especificarse y aprobarse durante el desarrollo o exposición de aplicaciones.',
    ruleIds: [
      'HDR-CSP-MISSING',
      'HDR-CSP-UNSAFE',
      'HDR-XFO-MISSING',
      'HDR-XCTO-MISSING',
      'HDR-REFERRER-MISSING',
      'HDR-PERMISSIONS-MISSING',
      'HDR-COOKIE-INSECURE',
      'HDR-COOKIE-NO-HTTPONLY',
      'HDR-COOKIE-NO-SAMESITE',
      'HDR-COOKIE-SAMESITE-NONE-INSECURE',
      'HDR-CORS-WILDCARD',
      'HDR-CORS-CREDENTIALS-INSECURE',
    ],
  },
  {
    id: 'ISO-A.8.8',
    framework: ComplianceFramework.ISO_27001,
    code: 'A.8.8',
    title: 'Gestión de Vulnerabilidades Técnicas',
    domain: 'Operaciones de Seguridad',
    description:
      'Se debe obtener información sobre las vulnerabilidades técnicas de los sistemas de información en uso, evaluar la exposición y tomar medidas oportunas.',
    ruleIds: ['VULN-KNOWN-CVE', 'HDR-OUTDATED-TECH', 'HDR-EOL-TECH'],
  },
  {
    id: 'ISO-A.8.9',
    framework: ComplianceFramework.ISO_27001,
    code: 'A.8.9',
    title: 'Gestión de Configuraciones y Endurecimiento',
    domain: 'Operaciones de Seguridad',
    description:
      'Las configuraciones de hardware, software, servicios y redes deben establecerse, documentarse, implementarse y monitorearse contra líneas base de seguridad.',
    ruleIds: [
      'HDR-SERVER-VERSION',
      'HDR-POWERED-BY',
      'PATH-DEBUG-INFO',
      'PATH-DIRECTORY-LISTING',
      'API-SWAGGER-EXPOSED',
      'API-ACTUATOR-ENV-EXPOSED',
      'API-GRAPHQL-INTROSPECTION',
      'API-METRICS-EXPOSED',
      'PATH-DEV-CONSOLE-EXPOSED',
    ],
  },
  {
    id: 'ISO-A.8.19',
    framework: ComplianceFramework.ISO_27001,
    code: 'A.8.19',
    title: 'Seguridad en Servicios de Red y Acceso Remoto',
    domain: 'Control de Acceso',
    description:
      'Los mecanismos de seguridad, niveles de servicio y requisitos de gestión de todos los servicios de red deben identificarse e implementarse.',
    ruleIds: [
      'SVC-REMOTE-DESKTOP',
      'SVC-DATABASE-EXPOSED',
      'SVC-FILE-SHARING',
      'SVC-ORCHESTRATION-EXPOSED',
      'SVC-DIRECTORY-SERVICE',
      'SVC-RPC-EXPOSED',
      'SVC-OPEN-PORT',
    ],
  },
  {
    id: 'ISO-A.8.23',
    framework: ComplianceFramework.ISO_27001,
    code: 'A.8.23',
    title: 'Filtrado Web y Prevención de Fugas de Información',
    domain: 'Seguridad de la Información',
    description:
      'El acceso a sitios web y la exposición de archivos corporativos debe gestionarse para reducir la exposición a software malicioso y divulgación no autorizada.',
    ruleIds: [
      'PATH-SECRETS-EXPOSED',
      'PATH-VCS-EXPOSED',
      'PATH-BACKUP-EXPOSED',
      'PATH-CONFIG-EXPOSED',
      'PATH-ADMIN-PANEL',
      'PATH-K8S-CONFIG-EXPOSED',
    ],
  },

  // =========================================================================
  // PCI-DSS v4.0
  // =========================================================================
  {
    id: 'PCI-1.3',
    framework: ComplianceFramework.PCI_DSS,
    code: 'Req 1.3',
    title: 'Restricción de Conexiones de Red Entrantes/Salientes',
    domain: 'Seguridad de Redes',
    description:
      'El tráfico de entrada y salida se restringe solo al tráfico necesario para el entorno de datos de titulares de tarjetas; todo lo demás se deniega explícitamente.',
    ruleIds: [
      'SVC-DATABASE-EXPOSED',
      'SVC-ORCHESTRATION-EXPOSED',
      'SVC-DIRECTORY-SERVICE',
      'SVC-RPC-EXPOSED',
      'SVC-FILE-SHARING',
      'SVC-OPEN-PORT',
    ],
  },
  {
    id: 'PCI-2.2',
    framework: ComplianceFramework.PCI_DSS,
    code: 'Req 2.2',
    title: 'Hardening y Servicios Innecesarios Deshabilitados',
    domain: 'Configuración Segura',
    description:
      'Los componentes del sistema se configuran según estándares de endurecimiento del sistema. Se eliminan o deshabilitan funciones, puertos y protocolos innecesarios.',
    ruleIds: [
      'SVC-CLEARTEXT-REMOTE-ADMIN',
      'SVC-CLEARTEXT-FILE-TRANSFER',
      'SVC-REMOTE-DESKTOP',
      'HDR-SERVER-VERSION',
      'HDR-POWERED-BY',
      'PATH-DEBUG-INFO',
      'PATH-DIRECTORY-LISTING',
    ],
  },
  {
    id: 'PCI-4.1',
    framework: ComplianceFramework.PCI_DSS,
    code: 'Req 4.1',
    title: 'Criptografía Fuerte en Tránsito de Redes Públicas',
    domain: 'Criptografía',
    description:
      'Se utilizan criptografía fuerte y protocolos de seguridad modernos (TLS 1.2 o superior, sin cifradores débiles) para salvaguardar datos en tránsito sobre redes abiertas.',
    ruleIds: [
      'TLS-LEGACY-PROTOCOL',
      'TLS-WEAK-KEY',
      'TLS-WEAK-SIGNATURE',
      'TLS-NOT-AVAILABLE',
      'HDR-HSTS-MISSING',
      'HDR-HSTS-SHORT',
      'HDR-HTTP-NO-REDIRECT',
      'SVC-CLEARTEXT-REMOTE-ADMIN',
      'SVC-CLEARTEXT-FILE-TRANSFER',
      'SVC-MAIL-CLEARTEXT',
    ],
  },
  {
    id: 'PCI-4.2.1',
    framework: ComplianceFramework.PCI_DSS,
    code: 'Req 4.2.1',
    title: 'Vigencia y Confianza de Certificados Digitales',
    domain: 'Criptografía',
    description:
      'Los certificados utilizados para comunicaciones TLS deben ser válidos, emitidos por una entidad de certificación de confianza y no estar caducados.',
    ruleIds: [
      'TLS-EXPIRED',
      'TLS-EXPIRING-7D',
      'TLS-EXPIRING-30D',
      'TLS-NOT-YET-VALID',
      'TLS-HOSTNAME-MISMATCH',
      'TLS-UNTRUSTED-CHAIN',
      'DNS-NO-CAA',
    ],
  },
  {
    id: 'PCI-6.4.3',
    framework: ComplianceFramework.PCI_DSS,
    code: 'Req 6.4.3',
    title: 'Protección e Integridad de Páginas Web y Scripts',
    domain: 'Desarrollo Seguro',
    description:
      'Todos los scripts y cabeceras de seguridad en páginas de pago y aplicaciones web se gestionan para prevenir manipulación (CSP, integridad, cookies seguras).',
    ruleIds: [
      'HDR-CSP-MISSING',
      'HDR-CSP-UNSAFE',
      'HDR-XFO-MISSING',
      'HDR-XCTO-MISSING',
      'HDR-COOKIE-INSECURE',
      'HDR-COOKIE-NO-HTTPONLY',
      'HDR-COOKIE-NO-SAMESITE',
      'HDR-CORS-WILDCARD',
      'HDR-CORS-CREDENTIALS-INSECURE',
    ],
  },
  {
    id: 'PCI-11.3',
    framework: ComplianceFramework.PCI_DSS,
    code: 'Req 11.3',
    title: 'Análisis Periódico de Vulnerabilidades Externas',
    domain: 'Evaluación de Seguridad',
    description:
      'Se realizan escaneos periódicos de vulnerabilidades externas sobre todos los componentes perimetrales y se mitigan las vulnerabilidades de severidad alta.',
    ruleIds: ['VULN-KNOWN-CVE', 'HDR-OUTDATED-TECH', 'HDR-EOL-TECH'],
  },

  // =========================================================================
  // SOC 2 Type II (Trust Services Criteria)
  // =========================================================================
  {
    id: 'SOC2-CC6.1',
    framework: ComplianceFramework.SOC_2,
    code: 'CC6.1',
    title: 'Controles de Acceso Lógico y Perimetral',
    domain: 'Control de Acceso',
    description:
      'La entidad implementa controles de acceso lógico sobre infraestructura y datos para prevenir accesos no autorizados desde Internet.',
    ruleIds: [
      'SVC-REMOTE-DESKTOP',
      'SVC-DATABASE-EXPOSED',
      'SVC-ORCHESTRATION-EXPOSED',
      'SVC-DIRECTORY-SERVICE',
      'PATH-ADMIN-PANEL',
      'PATH-K8S-CONFIG-EXPOSED',
    ],
  },
  {
    id: 'SOC2-CC6.6',
    framework: ComplianceFramework.SOC_2,
    code: 'CC6.6',
    title: 'Protección de Redes, DNS y Prevención de Suplantación',
    domain: 'Seguridad en Comunicaciones',
    description:
      'Se implementan salvaguardas perimetrales para proteger los límites de la red y las comunicaciones, evitando ataques de spoofing y phishing contra el dominio.',
    ruleIds: [
      'MAIL-SPF-MISSING',
      'MAIL-SPF-INVALID',
      'MAIL-SPF-PASS-ALL',
      'MAIL-DMARC-MISSING',
      'MAIL-DMARC-INVALID',
      'MAIL-DKIM-NOT-FOUND',
      'DNS-NO-DNSSEC',
      'DNS-NO-CAA',
      'EMAIL-IP-BLACKLISTED',
    ],
  },
  {
    id: 'SOC2-CC6.7',
    framework: ComplianceFramework.SOC_2,
    code: 'CC6.7',
    title: 'Cifrado de Datos en Transmisión',
    domain: 'Confidencialidad',
    description:
      'La entidad protege la información transmitida a través de redes públicas utilizando protocolos de cifrado robustos y certificados digitales vigentes.',
    ruleIds: [
      'TLS-EXPIRED',
      'TLS-EXPIRING-7D',
      'TLS-LEGACY-PROTOCOL',
      'TLS-WEAK-KEY',
      'TLS-UNTRUSTED-CHAIN',
      'HDR-HSTS-MISSING',
      'HDR-HTTP-NO-REDIRECT',
      'SVC-CLEARTEXT-REMOTE-ADMIN',
      'SVC-CLEARTEXT-FILE-TRANSFER',
      'SVC-MAIL-CLEARTEXT',
    ],
  },
  {
    id: 'SOC2-CC7.1',
    framework: ComplianceFramework.SOC_2,
    code: 'CC7.1',
    title: 'Detección y Gestión Continua de Vulnerabilidades',
    domain: 'Monitoreo de Operaciones',
    description:
      'La infraestructura se monitorea continuamente para detectar vulnerabilidades de seguridad, software desactualizado y malas configuraciones perimetrales.',
    ruleIds: [
      'VULN-KNOWN-CVE',
      'HDR-OUTDATED-TECH',
      'HDR-EOL-TECH',
      'PATH-SECRETS-EXPOSED',
      'PATH-VCS-EXPOSED',
      'PATH-BACKUP-EXPOSED',
      'PATH-CONFIG-EXPOSED',
      'API-ACTUATOR-ENV-EXPOSED',
    ],
  },

  // =========================================================================
  // NIST Cybersecurity Framework (CSF 2.0)
  // =========================================================================
  {
    id: 'NIST-PR.AC-3',
    framework: ComplianceFramework.NIST_CSF,
    code: 'PR.AC-3',
    title: 'Gestión y Restricción de Accesos Remotos',
    domain: 'Proteger (Protect - PR)',
    description:
      'Los accesos remotos y las interfaces de administración del sistema son gestionados, autenticados y restringidos desde redes externas no seguras.',
    ruleIds: [
      'SVC-REMOTE-DESKTOP',
      'SVC-CLEARTEXT-REMOTE-ADMIN',
      'SVC-DIRECTORY-SERVICE',
      'PATH-ADMIN-PANEL',
      'PATH-DEV-CONSOLE-EXPOSED',
    ],
  },
  {
    id: 'NIST-PR.DS-2',
    framework: ComplianceFramework.NIST_CSF,
    code: 'PR.DS-2',
    title: 'Protección de Datos en Tránsito',
    domain: 'Proteger (Protect - PR)',
    description:
      'Los datos en tránsito están protegidos de acuerdo con los objetivos de confidencialidad e integridad de la organización mediante criptografía robusta.',
    ruleIds: [
      'TLS-EXPIRED',
      'TLS-EXPIRING-7D',
      'TLS-LEGACY-PROTOCOL',
      'TLS-WEAK-KEY',
      'TLS-WEAK-SIGNATURE',
      'TLS-NOT-AVAILABLE',
      'HDR-HSTS-MISSING',
      'HDR-HTTP-NO-REDIRECT',
      'SVC-CLEARTEXT-FILE-TRANSFER',
    ],
  },
  {
    id: 'NIST-PR.DS-5',
    framework: ComplianceFramework.NIST_CSF,
    code: 'PR.DS-5',
    title: 'Protección contra Fuga de Datos y Secretos Expuestos',
    domain: 'Proteger (Protect - PR)',
    description:
      'Se implementan mecanismos de protección contra la fuga o publicación involuntaria de secretos, credenciales o código fuente en la superficie externa.',
    ruleIds: [
      'PATH-SECRETS-EXPOSED',
      'PATH-VCS-EXPOSED',
      'PATH-BACKUP-EXPOSED',
      'PATH-CONFIG-EXPOSED',
      'PATH-K8S-CONFIG-EXPOSED',
      'API-ACTUATOR-ENV-EXPOSED',
    ],
  },
  {
    id: 'NIST-PR.PS-1',
    framework: ComplianceFramework.NIST_CSF,
    code: 'PR.PS-1',
    title: 'Líneas Base de Configuración Segura y Endurecimiento',
    domain: 'Proteger (Protect - PR)',
    description:
      'Las plataformas se configuran de acuerdo con estándares de endurecimiento y se mitigan malas configuraciones que faciliten ataques web.',
    ruleIds: [
      'HDR-CSP-MISSING',
      'HDR-CSP-UNSAFE',
      'HDR-XFO-MISSING',
      'HDR-XCTO-MISSING',
      'HDR-SERVER-VERSION',
      'HDR-POWERED-BY',
      'HDR-COOKIE-INSECURE',
      'HDR-CORS-WILDCARD',
    ],
  },
  {
    id: 'NIST-RS.MI-3',
    framework: ComplianceFramework.NIST_CSF,
    code: 'RS.MI-3',
    title: 'Mitigación de Vulnerabilidades Conocidas',
    domain: 'Responder (Respond - RS)',
    description:
      'Las vulnerabilidades de seguridad conocidas (CVEs) identificadas en activos de cara a Internet son evaluadas y mitigadas oportunamente.',
    ruleIds: ['VULN-KNOWN-CVE', 'HDR-OUTDATED-TECH', 'HDR-EOL-TECH'],
  },

  // =========================================================================
  // CIS Critical Security Controls v8
  // =========================================================================
  {
    id: 'CIS-4.1',
    framework: ComplianceFramework.CIS_CONTROLS,
    code: 'CIS 4.1',
    title: 'Configuración Segura de Activos Empresariales',
    domain: 'Configuración Segura',
    description:
      'Establecer y mantener procesos de configuración segura para los activos empresariales (servidores web, cortafuegos y servicios de cara a Internet).',
    ruleIds: [
      'HDR-CSP-MISSING',
      'HDR-XFO-MISSING',
      'HDR-XCTO-MISSING',
      'HDR-SERVER-VERSION',
      'HDR-POWERED-BY',
      'PATH-DEBUG-INFO',
      'PATH-DIRECTORY-LISTING',
      'API-METRICS-EXPOSED',
    ],
  },
  {
    id: 'CIS-7.1',
    framework: ComplianceFramework.CIS_CONTROLS,
    code: 'CIS 7.1',
    title: 'Gestión Continua de Vulnerabilidades',
    domain: 'Gestión de Vulnerabilidades',
    description:
      'Realizar análisis de vulnerabilidades automatizados y sistemáticos para identificar software desactualizado o con fallos de seguridad.',
    ruleIds: ['VULN-KNOWN-CVE', 'HDR-OUTDATED-TECH', 'HDR-EOL-TECH'],
  },
  {
    id: 'CIS-9.2',
    framework: ComplianceFramework.CIS_CONTROLS,
    code: 'CIS 9.2',
    title: 'Control de Puertos, Protocolos y Servicios de Red',
    domain: 'Seguridad en Redes',
    description:
      'Garantizar que solo los puertos, protocolos y servicios de red expresamente autorizados y necesarios para el negocio permanezcan accesibles en Internet.',
    ruleIds: [
      'SVC-DATABASE-EXPOSED',
      'SVC-ORCHESTRATION-EXPOSED',
      'SVC-DIRECTORY-SERVICE',
      'SVC-REMOTE-DESKTOP',
      'SVC-CLEARTEXT-REMOTE-ADMIN',
      'SVC-CLEARTEXT-FILE-TRANSFER',
      'SVC-FILE-SHARING',
      'SVC-RPC-EXPOSED',
    ],
  },
  {
    id: 'CIS-10.4',
    framework: ComplianceFramework.CIS_CONTROLS,
    code: 'CIS 10.4',
    title: 'Cifrado de Datos en Tránsito en Comunicaciones Externas',
    domain: 'Protección de Datos',
    description:
      'Requerir y aplicar cifrado de extremo a extremo mediante protocolos criptográficos modernos (TLS 1.2+) para cualquier transmisión de información.',
    ruleIds: [
      'TLS-EXPIRED',
      'TLS-LEGACY-PROTOCOL',
      'TLS-WEAK-KEY',
      'TLS-UNTRUSTED-CHAIN',
      'HDR-HSTS-MISSING',
      'HDR-HTTP-NO-REDIRECT',
      'MAIL-SPF-MISSING',
      'MAIL-DMARC-MISSING',
    ],
  },
];
