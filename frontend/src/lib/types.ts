/** Tipos de las respuestas de la API (backend/src). */

export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';
export type AssetType = 'DOMAIN' | 'IP';
export type ScanType = 'PORT_SCAN' | 'WEB_HEADERS' | 'SSL_CERT' | 'SENSITIVE_PATHS';
export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'OPEN' | 'RESOLVED' | 'ACCEPTED' | 'FALSE_POSITIVE';
export type FindingCategory = 'EXPOSED_SERVICE' | 'HTTP_HEADERS' | 'TLS_CERTIFICATE' | 'SENSITIVE_PATH';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export type SeverityCounts = Record<Severity, number>;

export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  organizationId: string;
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
  isActive: boolean;
  authorizationConfirmed: boolean;
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
  reviewNote: string | null;
  asset: { id: string; type: AssetType; value: string; name: string | null };
  reviewedBy: { id: string; fullName: string; email: string } | null;
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

export interface HistoryPoint {
  computedAt: string;
  score: number | null;
  grade: Grade | null;
  counts: SeverityCounts;
  trigger: string;
  scanId: string | null;
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
  isActive: boolean;
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
  exposure: { scanId: string | null; scannedAt: string | null; targetAddress: string | null; openPorts: OpenPort[] };
  latestScans: Array<{ id: string; type: ScanType; status: ScanStatus; createdAt: string; finishedAt: string | null; errorMessage: string | null }>;
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
