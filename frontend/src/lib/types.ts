/** Tipos de las respuestas de la API (backend/src). */

export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';
export type AssetType = 'DOMAIN' | 'IP' | 'CLOUD_ACCOUNT';
export type AssetCriticality = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type ScanType = 'PORT_SCAN' | 'WEB_HEADERS' | 'SSL_CERT' | 'SENSITIVE_PATHS' | 'EMAIL_SECURITY' | 'SUBDOMAIN_DISCOVERY';
export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus =
  | 'OPEN'
  | 'IN_PROGRESS'
  | 'VERIFYING'
  | 'RESOLVED'
  | 'ACCEPTED'
  | 'FALSE_POSITIVE';
export type FindingCategory =
  | 'EXPOSED_SERVICE'
  | 'VULNERABLE_SOFTWARE'
  | 'HTTP_HEADERS'
  | 'TLS_CERTIFICATE'
  | 'SENSITIVE_PATH'
  | 'EMAIL_SECURITY'
  | 'CLOUD_IAM'
  | 'CLOUD_STORAGE'
  | 'CLOUD_NETWORK'
  | 'CLOUD_COMPUTE'
  | 'CLOUD_DATABASE'
  | 'CLOUD_LOGGING';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export type ScanSource = 'MANUAL' | 'SCHEDULED';
export type AlertType = 'NEW_OPEN_PORT' | 'CERT_EXPIRING' | 'CRITICAL_FINDING' | 'NEW_SUBDOMAIN' | 'SCORE_ANOMALY';
export type AlertChannelType = 'EMAIL' | 'WEBHOOK';
export type MonitoringFrequency = 'OFF' | 'DAILY' | 'WEEKLY';
export type ReportType = 'EXECUTIVE' | 'TECHNICAL';
export type DeliveryStatus = 'SENT' | 'FAILED' | 'SKIPPED';
export type VerificationMethod = 'DNS_TXT' | 'HTTP_FILE' | 'INHERITED' | 'PRE_AUTHORIZED';

export type SeverityCounts = Record<Severity, number>;

export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  organizationId: string;
  emailVerified?: boolean;
  pendingEmail?: string | null;
}

export interface AuthResponse {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: string;
  user: AuthUser;
}

export interface Paginated<T> {
  items: T[];
  meta: { total: number; page: number; pageSize: number; totalPages: number };
}

export interface Asset {
  id: string;
  organizationId: string;
  type: AssetType;
  value: string;
  name: string | null;
  description: string | null;
  criticality?: AssetCriticality;
  tags?: string[];
  isActive: boolean;
  authorizationConfirmed: boolean;
  verifiedAt?: string | null;
  verificationMethod?: VerificationMethod | null;
  verificationScope?: string | null;
  lastScannedAt: string | null;
  createdAt: string;
  createdBy?: { id: string; fullName: string; email: string } | null;
  _count?: { scans: number };
}

export interface ScanSummaryFindings {
  created: number;
  updated: number;
  reopened: number;
  resolved: number;
}

export interface Scan {
  id: string;
  assetId: string;
  type: ScanType;
  status: ScanStatus;
  source: ScanSource;
  targetAddress: string | null;
  summary: (Record<string, unknown> & { findings?: ScanSummaryFindings; openPortsCount?: number; findingsCount?: number }) | null;
  errorMessage: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
  asset: { id: string; type: AssetType; value: string; name: string | null };
  requestedBy: { id: string; fullName: string; email: string } | null;
}

export interface Finding {
  id: string;
  assetId: string;
  category: FindingCategory;
  ruleId: string;
  severity: Severity;
  cvssScore: string | number | null;
  status: FindingStatus;
  title: string;
  description: string;
  recommendation: string;
  location: string;
  evidence: Record<string, unknown> | null;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  assignedToId?: string | null;
  assignedTo?: { id: string; fullName: string; email: string } | null;
  dueDate?: string | null;
  remediationNote?: string | null;
  reviewNote: string | null;
  asset: { id: string; type: AssetType; value: string; name: string | null };
  reviewedBy: { id: string; fullName: string; email: string } | null;
  remediationGuide?: RemediationGuide;
  sla?: FindingSla;
}

export type SlaStatus = 'OVERDUE' | 'APPROACHING' | 'ON_TRACK' | 'RESOLVED' | 'NO_SLA';

export interface FindingSla {
  status: SlaStatus;
  hoursRemaining: number | null;
  isOverdue: boolean;
  isApproaching: boolean;
  dueDate: string | null;
  label: string;
}

export interface UserAssignee {
  id: string;
  fullName: string;
  email: string;
  role: UserRole;
}

export interface FindingsSlaSummary {
  overdue: number;
  approaching: number;
  onTrack: number;
  noSla: number;
  unassigned: number;
  assigned: number;
}

export interface FindingsSummary {
  total: number;
  bySeverity: SeverityCounts;
  byCategory: Record<string, number>;
  severityOrder: Severity[];
  sla?: FindingsSlaSummary;
}

export interface RemediationSnippet {
  platform:
    | 'Nginx'
    | 'Apache'
    | 'Cloudflare'
    | 'Docker'
    | 'Spring Boot'
    | 'Node.js'
    | 'AWS CLI'
    | 'Azure CLI'
    | 'Terraform'
    | 'General';
  code: string;
  description: string;
}

export interface RemediationGuide {
  ruleId: string;
  owasp?: string;
  cwe?: string;
  summary: string;
  verificationCommand?: string;
  snippets: RemediationSnippet[];
}

export interface DetectedTechnology {
  name: string;
  category: 'Web Server' | 'Framework' | 'CMS' | 'Programming Language' | 'Frontend Library' | 'CDN/Proxy';
  version?: string;
  confidence: number;
  eol?: boolean;
  eolNotice?: string;
  matchedFrom?: string;
}

export interface BusinessImpact {
  area: 'Operativa' | 'Financiera' | 'Regulatoria/Legal' | 'Reputacional';
  severity: 'CRÍTICO' | 'ALTO' | 'MEDIO' | 'BAJO';
  description: string;
}

export interface StrategicPriority {
  order: number;
  title: string;
  action: string;
  businessJustification: string;
  affectedTarget: string;
}

export interface ExecutiveBusinessSummary {
  headline: string;
  riskLevel: 'CRÍTICO' | 'ALTO' | 'MODERADO' | 'BAJO';
  scoreOverview: {
    score: number | null;
    grade: string | null;
    trendLabel: string;
  };
  executiveOverview: string;
  businessImpacts: BusinessImpact[];
  topPriorities: StrategicPriority[];
  technicalDebtSummary?: string;
  generatedAt: string;
  provider: 'ai' | 'heuristic-expert';
}

export interface RetestFindingResult {
  finding: Finding;
  stillReproducible: boolean;
  message: string;
  testedAt: string;
  details?: Record<string, unknown>;
}

export interface TopFinding {
  id: string;
  assetId: string;
  category: FindingCategory;
  ruleId: string;
  severity: Severity;
  cvssScore: string | number | null;
  title: string;
  location: string;
  recommendation: string;
  firstSeenAt: string;
  lastSeenAt: string;
  asset: { id: string; value: string; name: string | null; type: AssetType };
}

export interface HistoryPointAnomaly {
  drop: number;
  zScore?: number | null;
  severity: Severity;
}

export interface HistoryPoint {
  computedAt: string;
  score: number | null;
  grade: Grade | null;
  counts: SeverityCounts;
  trigger: string;
  scanId: string | null;
  anomaly?: HistoryPointAnomaly | null;
}

export interface Overview {
  generatedAt: string;
  securityScore: {
    score: number | null;
    grade: Grade | null;
    label: string;
    description: string;
    scoredAssets: number;
    totalAssets: number;
    lastSnapshotAt: string | null;
    trend: {
      sincePrevious: number | null;
      sinceLastWeek: number | null;
      previousScore: number | null;
      lastWeekScore: number | null;
    };
  };
  findings: {
    open: number;
    bySeverity: SeverityCounts;
    byCategory: Partial<Record<FindingCategory, number>>;
    byStatus: Record<FindingStatus, number>;
  };
  assets: { total: number; active: number; inactive: number };
  scans: {
    inProgress: number;
    completedLast24h: number;
    last7Days: Record<ScanStatus, number>;
    lastCompletedAt: string | null;
  };
  topFindings: TopFinding[];
  recentScans: Array<{
    id: string;
    type: ScanType;
    status: ScanStatus;
    createdAt: string;
    finishedAt: string | null;
    errorMessage: string | null;
    asset: { id: string; value: string; name: string | null };
  }>;
}

export interface DashboardAsset {
  id: string;
  type: AssetType;
  value: string;
  name: string | null;
  criticality?: AssetCriticality;
  tags?: string[];
  isActive: boolean;
  verified: boolean;
  verificationMethod: VerificationMethod | null;
  scored: boolean;
  score: number | null;
  grade: Grade | null;
  openFindings: number;
  bySeverity: SeverityCounts;
  lastScannedAt: string | null;
  lastScanByType: Partial<Record<ScanType, string | null>>;
  totalScans: number;
}

export interface Penalty {
  severity: Severity;
  count: number;
  weight: number;
  cap: number;
  penalty: number;
  capped: boolean;
}

export interface AssetScore {
  scope: 'ASSET';
  scored: boolean;
  score: number | null;
  grade: Grade | null;
  label: string;
  description: string;
  counts: SeverityCounts;
  penalties: Penalty[];
  totalPenalty: number;
}

export interface OpenPort {
  port: number;
  protocol: string;
  serviceName: string | null;
  product: string | null;
  version: string | null;
  tunnel: string | null;
}

export interface AssetDashboard {
  asset: Asset;
  securityScore: AssetScore;
  history: HistoryPoint[];
  findings: { open: number; byCategory: Partial<Record<FindingCategory, number>>; items: TopFinding[] };
  exposure: {
    scanId: string | null;
    scannedAt: string | null;
    targetAddress: string | null;
    openPorts: OpenPort[];
    technologies?: DetectedTechnology[];
  };
  latestScans: Array<{
    id: string;
    type: ScanType;
    status: ScanStatus;
    createdAt: string;
    finishedAt: string | null;
    errorMessage: string | null;
    summary: Record<string, unknown> | null;
  }>;
}

export interface OrgHistory {
  days: number;
  points: HistoryPoint[];
}

export interface OrgUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  isActive: boolean;
  mfaEnabled: boolean;
  lastLoginAt: string | null;
  passwordChangedAt: string | null;
  organizationId: string;
  createdAt: string;
  updatedAt: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  isActive: boolean;
  createdAt: string;
  _count: { users: number; assets: number; scans: number };
}

export interface DeliveryResult {
  channelId: string;
  channelType: AlertChannelType;
  channelName: string;
  status: DeliveryStatus;
  detail?: string;
  error?: string;
  at: string;
  attempts?: number;
  lastAttemptAt?: string;
  nextRetryAt?: string | null;
}

export interface AlertItem {
  id: string;
  type: AlertType;
  severity: Severity;
  title: string;
  message: string;
  data: Record<string, unknown> | null;
  deliveries: DeliveryResult[] | null;
  acknowledgedAt: string | null;
  createdAt: string;
  scanId: string | null;
  asset: { id: string; value: string; name: string | null; type: AssetType } | null;
  acknowledgedBy: { id: string; fullName: string; email: string } | null;
}

export interface AlertsSummary {
  unacknowledged: number;
  bySeverity: SeverityCounts;
  lastAlertAt: string | null;
}

export interface AlertChannel {
  id: string;
  type: AlertChannelType;
  name: string;
  /** Las URL de webhook llegan enmascaradas. */
  target: string;
  signingSecret?: string | null;
  minSeverity: Severity;
  isActive: boolean;
  lastDeliveryAt: string | null;
  lastDeliveryStatus: DeliveryStatus | null;
  lastDeliveryError: string | null;
  createdAt: string;
  createdBy: { id: string; fullName: string } | null;
}

export interface MonitoringStatus {
  frequency: MonitoringFrequency;
  periodHours: number | null;
  schedulerEnabled: boolean;
  lastScheduledScanAt: string | null;
  assets: Array<{
    id: string;
    value: string;
    name: string | null;
    isActive: boolean;
    authorizationConfirmed: boolean;
    verifiedAt: string | null;
    lastScheduledScanAt: string | null;
    lastScannedAt: string | null;
    monitored: boolean;
    nextRunAt: string | null;
    due: boolean;
  }>;
}

export interface ReportRecord {
  id: string;
  type: ReportType;
  score: number | null;
  grade: Grade | null;
  openFindings: number;
  pages: number;
  sizeBytes: number;
  createdAt: string;
  asset: { id: string; value: string; name: string | null } | null;
  generatedBy: { id: string; fullName: string } | null;
}

export interface VerificationAttempt {
  method: 'DNS_TXT' | 'HTTP_FILE';
  target: string;
  ok: boolean;
  detail: string;
}

export interface AssetVerification {
  assetId: string;
  type: AssetType;
  value: string;
  required: boolean;
  verified: boolean;
  verifiedAt: string | null;
  method: VerificationMethod | null;
  scope: string | null;
  checkedAt: string | null;
  error: string | null;
  proof: string;
  dns: { type: 'TXT'; value: string; recordName: string; alternatives: string[] } | null;
  file: { content: string; urls: string[] };
  /** Solo en la respuesta de POST /assets/:id/verify. */
  attempts?: VerificationAttempt[];
  success?: boolean;
}

/** Subdominio descubierto en Certificate Transparency. */
export interface DiscoveredHost {
  id: string;
  hostname: string;
  resolves: boolean;
  addresses: string[];
  /** Resuelve a una IP privada: el certificado revela infraestructura interna. */
  internal: boolean;
  wildcard: boolean;
  lastCertificateAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  ignored: boolean;
  inventoryAssetId: string | null;
}

export interface DiscoveredHosts {
  asset: { id: string; type: AssetType; value: string };
  lastDiscovery: { scanId: string; finishedAt: string | null; summary: { source?: string; truncated?: boolean } | null } | null;
  summary: { total: number; resolving: number; pending: number; ignored: number; inInventory: number };
  items: DiscoveredHost[];
}

export interface ImportDiscoveredResult {
  created: Array<{ hostname: string; assetId: string; verified: boolean }>;
  failed: Array<{ hostname: string; reason: string }>;
}

/** Resumen del escaneo EMAIL_SECURITY. */
export interface EmailSecuritySummary {
  receivesMail: boolean;
  mx: string[];
  spf: { record: string | null; records: number; lookups: number | null; all: string | null; errors: string[] };
  dmarc: { status: 'missing' | 'invalid' | 'ok'; record: string | null; domain: string | null; inherited: boolean; policy: string | null };
  dkim: { checked: boolean; selectors: Array<{ selector: string; keyType: string; bits: number | null }> };
  mtaSts?: {
    status: 'valid' | 'missing' | 'invalid';
    policyId: string | null;
    mode: string | null;
    mx: string[];
    error?: string;
  };
  tlsRpt?: {
    status: 'valid' | 'missing' | 'invalid';
    record: string | null;
    rua: string[];
    error?: string;
  };
  caa?: {
    status: 'valid' | 'missing' | 'invalid';
    domain: string;
    inherited: boolean;
    issue: string[];
    issuewild: string[];
    iodef: string[];
    error?: string;
  };
  dnssec?: {
    status: 'secure' | 'insecure' | 'bogus' | 'indeterminate';
    domain: string;
    adFlag: boolean;
    dsCount: number;
    dnskeyCount: number;
    rrsigCount: number;
    error?: string;
  };
  dnsbl?: {
    checked: boolean;
    totalIpsChecked: number;
    clean: boolean;
    listings: Array<{
      ip: string;
      exchange: string;
      provider: string;
      returnCodes: string[];
      txt?: string;
    }>;
  };
}

/** Un CVE en la evidencia de un hallazgo VULN-KNOWN-CVE. */
export interface CveEvidence {
  id: string;
  cvss: number | null;
  severity: Severity;
  published: string | null;
  kev: boolean;
  kevDueDate: string | null;
  ransomware?: boolean;
  epss?: number | null;
  epssPercentile?: number | null;
  description: string;
  url: string;
}

/** Respuesta del primer paso del login cuando la cuenta exige el segundo factor. */
export interface MfaChallenge {
  mfaRequired: true;
  mfaToken: string;
}

export interface MfaStatus {
  enabled: boolean;
  enabledAt: string | null;
  recoveryCodesLeft: number;
}

export interface MfaSetup {
  secret: string;
  otpauthUrl: string;
  digits: number;
  periodSeconds: number;
}

export interface Invitation {
  id: string;
  email: string;
  role: UserRole;
  expiresAt: string;
  usedAt: string | null;
  deliveryStatus: 'SENT' | 'FAILED' | 'SKIPPED' | null;
  deliveryError: string | null;
  createdAt: string;
  createdBy: { id: string; fullName: string } | null;
  expired: boolean;
}

export interface InvitationInfo {
  email: string;
  role: UserRole;
  organizationName: string;
  expiresAt: string;
}

/** Fila del registro de auditoría (RNF-06). */
export interface AuditEntry {
  id: string;
  action: string;
  actorId: string | null;
  actorEmail: string | null;
  actorName: string | null;
  targetType: string | null;
  targetId: string | null;
  targetLabel: string | null;
  detail: Record<string, unknown> | null;
  ip: string | null;
  createdAt: string;
}

export interface RetentionResult {
  executedAt: string;
  triggeredBy: string;
  scansPurged: number;
  scanPortsPurged: number;
  tokensPurged: number;
  loginAttemptsPurged: number;
  auditLogsPurged: number;
  reportsPurged: number;
}

export interface RetentionStatus {
  enabled: boolean;
  scansRetentionDays: number;
  auditRetentionDays: number;
  tokensRetentionDays: number;
  reportsRetentionDays: number;
  lastRunAt: string | null;
  lastResult: RetentionResult | null;
}

export type TriageVerdict = 'PROBABLE_FALSE_POSITIVE' | 'NEEDS_VERIFICATION' | 'CONFIRMED_TRUE_POSITIVE';

export type TriageConfidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type TriageRecommendedAction = 'MARK_FALSE_POSITIVE' | 'ACCEPT_RISK' | 'REMEDIATE' | 'RETEST';

export interface TriageContextFactor {
  factor: string;
  impact: 'INCREASES_FP_PROBABILITY' | 'DECREASES_FP_PROBABILITY' | 'NEUTRAL';
  detail: string;
}

export interface FindingTriageAnalysis {
  findingId: string;
  verdict: TriageVerdict;
  confidence: TriageConfidence;
  confidenceScore: number;
  summary: string;
  reasoning: string[];
  contextFactors: TriageContextFactor[];
  recommendedAction: TriageRecommendedAction;
  suggestedNote: string;
  evaluatedAt: string;
  provider: 'ai' | 'heuristic-expert';
}

export interface ApiKeyItem {
  id: string;
  organizationId: string;
  name: string;
  keyPrefix: string;
  scopes: string[];
  isActive: boolean;
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
  updatedAt: string;
  createdBy?: {
    id: string;
    fullName: string;
    email: string;
  } | null;
}

export interface CreateApiKeyInput {
  name: string;
  scopes?: string[];
  expiresAt?: string;
}

export interface CreatedApiKeyResponse extends ApiKeyItem {
  rawKey: string;
}

// Compliance Framework Mapping
export type ComplianceFramework = 'ISO_27001' | 'PCI_DSS' | 'SOC_2' | 'NIST_CSF' | 'CIS_CONTROLS';

export interface FrameworkMetadata {
  id: ComplianceFramework;
  name: string;
  version: string;
  description: string;
  authority: string;
  iconName: string;
}

export interface ControlFindingSummary {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  cvssScore: number | null;
  location: string;
  assetId: string;
  assetValue: string;
  assetName: string | null;
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

export interface ControlEvaluationResult {
  control: ComplianceControlDefinition;
  status: 'COMPLIANT' | 'NON_COMPLIANT';
  affectedAssetsCount: number;
  failingFindingsCount: number;
  worstSeverity: Severity | null;
  failingFindings: ControlFindingSummary[];
}

export interface FrameworkSummary {
  metadata: FrameworkMetadata;
  totalControls: number;
  passedControls: number;
  failedControls: number;
  compliancePercentage: number;
  failingFindingsCount: number;
  worstSeverity: Severity | null;
}

export interface TopFailingControl {
  framework: ComplianceFramework;
  code: string;
  title: string;
  domain: string;
  worstSeverity: Severity;
  failingFindingsCount: number;
  affectedAssetsCount: number;
}

export interface ComplianceOverview {
  globalCompliancePercentage: number;
  totalFrameworks: number;
  totalEvaluatedControls: number;
  frameworks: FrameworkSummary[];
  topFailingControls: TopFailingControl[];
}

export interface FrameworkDetailsResponse {
  metadata: FrameworkMetadata;
  summary: FrameworkSummary;
  controls: ControlEvaluationResult[];
}

// Cloud Security Posture Management (CSPM)
export type CloudProvider = 'AWS' | 'AZURE';
export type CloudAuthType = 'ROLE_ARN' | 'ACCESS_KEYS' | 'SERVICE_PRINCIPAL';
export type CloudAccountStatus = 'PENDING' | 'CONNECTED' | 'ERROR' | 'DISCONNECTED';

export type CloudResourceType =
  | 'AWS_S3_BUCKET'
  | 'AWS_IAM_USER'
  | 'AWS_IAM_ROLE'
  | 'AWS_SECURITY_GROUP'
  | 'AWS_EC2_INSTANCE'
  | 'AWS_RDS_INSTANCE'
  | 'AWS_CLOUDTRAIL'
  | 'AWS_VPC'
  | 'AZURE_STORAGE_ACCOUNT'
  | 'AZURE_BLOB_CONTAINER'
  | 'AZURE_NSG'
  | 'AZURE_VM'
  | 'AZURE_SQL_DATABASE'
  | 'AZURE_ACTIVITY_LOG'
  | 'AZURE_VNET'
  | 'OTHER';

export interface CloudAccountItem {
  id: string;
  organizationId: string;
  provider: CloudProvider;
  name: string;
  authType: CloudAuthType;
  status: CloudAccountStatus;
  accountOrSubscriptionId: string;
  azureTenantId?: string | null;
  awsRoleArn?: string | null;
  awsExternalId?: string | null;
  monitoredRegions: string[];
  assetId?: string | null;
  lastAuditedAt?: string | null;
  lastAuditError?: string | null;
  resourceCount: number;
  failingFindingCount: number;
  hasCredentialsStored?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CloudOnboardingTemplate {
  awsExternalId: string;
  awsCloudFormationYaml: string;
  awsCliSnippet: string;
  azureCliSnippet: string;
}

export interface CloudVerificationResult {
  valid: boolean;
  accountId?: string;
  arn?: string;
  userId?: string;
  assumedRole?: boolean;
  subscriptionId?: string;
  displayName?: string;
  state?: string;
  tenantId?: string;
  latencyMs: number;
  error?: string;
}

export interface CreateCloudAccountInput {
  provider: CloudProvider;
  name: string;
  authType: CloudAuthType;
  accountOrSubscriptionId: string;
  azureTenantId?: string;
  azureClientId?: string;
  azureClientSecret?: string;
  awsRoleArn?: string;
  awsExternalId?: string;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  awsSessionToken?: string;
  monitoredRegions?: string[];
  verifyOnCreate?: boolean;
}

export interface TestCloudConnectionInput {
  provider: CloudProvider;
  authType: CloudAuthType;
  accountOrSubscriptionId: string;
  azureTenantId?: string;
  azureClientId?: string;
  azureClientSecret?: string;
  awsRoleArn?: string;
  awsExternalId?: string;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  awsSessionToken?: string;
}

export interface CspmRuleDefinition {
  ruleId: string;
  provider: CloudProvider;
  category: FindingCategory;
  severity: Severity;
  cvssScore: number;
  title: string;
  description: string;
  recommendation: string;
  remediationCli: string;
  remediationIac: string;
  complianceControlIds: string[];
}

export interface CloudResourceItem {
  id: string;
  organizationId: string;
  cloudAccountId: string;
  provider: CloudProvider;
  resourceType: CloudResourceType;
  nativeId: string;
  name: string;
  region?: string | null;
  configuration?: Record<string, unknown> | null;
  tags?: Record<string, string> | null;
  hasActiveFindings: boolean;
  createdAt: string;
  updatedAt: string;
  cloudAccount?: {
    id: string;
    name: string;
    provider: CloudProvider;
    accountOrSubscriptionId: string;
  };
  findings?: Array<{
    id: string;
    ruleId: string;
    title: string;
    severity: Severity;
    category: FindingCategory;
    status: FindingStatus;
  }>;
}

export interface CloudAuditStats {
  resourcesDiscovered: number;
  findingsCreated: number;
  findingsUpdated: number;
  findingsReopened: number;
  findingsResolved: number;
  activeFindings: number;
  bySeverity: SeverityCounts;
  byCategory: Partial<Record<FindingCategory, number>>;
  score: number | null;
  grade: string | null;
}

export interface CloudAuditResponse {
  account: CloudAccountItem;
  simulated: boolean;
  evaluatedRulesCount: number;
  evaluatedAt: string;
  durationMs: number;
  warnings: string[];
  stats: CloudAuditStats;
}

export interface CloudPostureSummary {
  accounts: {
    total: number;
    connected: number;
    error: number;
    pending: number;
    byProvider: { AWS: number; AZURE: number };
  };
  resources: {
    total: number;
    withFindings: number;
    clean: number;
    byProvider: { AWS: number; AZURE: number };
    byType: Record<string, number>;
  };
  findings: {
    totalOpen: number;
    bySeverity: SeverityCounts;
    byCategory: Record<string, number>;
  };
}

