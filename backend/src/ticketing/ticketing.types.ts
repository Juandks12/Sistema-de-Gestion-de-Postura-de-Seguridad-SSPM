import { FindingCategory, FindingSeverity, TicketingAutoCreateThreshold, TicketingProvider } from '@prisma/client';

export { TicketingAutoCreateThreshold, TicketingProvider };

export interface JiraCredentials {
  email: string;
  apiToken: string;
}

export interface AzureBoardsCredentials {
  personalAccessToken: string;
  organizationName?: string;
}

export interface TicketingFindingPayload {
  findingId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  cvssScore: number | null;
  location: string;
  ruleId: string;
  category: FindingCategory;
  cweId?: string;
  owaspCategory?: string;
  mitreAttackTechnique?: string;
  complianceControls?: Array<{ code: string; title: string; frameworkName: string }>;
  recommendation: string;
  evidence?: unknown;
  assetValue: string;
  dueDate?: Date | null;
  customNotes?: string;
}

export interface CreatedTicketResult {
  key: string;
  url: string;
  status: string;
}

export interface TicketStatusResult {
  key: string;
  status: string;
  isClosed: boolean;
  assignee?: string | null;
  updatedAt?: Date;
}

export interface TestConnectionResult {
  ok: boolean;
  provider: TicketingProvider;
  accountName?: string;
  projectName?: string;
  availableIssueTypes: string[];
  error?: string;
}

export interface TicketingConfigSummary {
  configured: boolean;
  provider?: TicketingProvider;
  enabled?: boolean;
  instanceUrl?: string;
  projectKey?: string;
  issueType?: string;
  autoCreateThreshold?: TicketingAutoCreateThreshold;
  lastTestedAt?: Date | null;
  lastTestStatus?: string | null;
  lastTestError?: string | null;
  maskedCredentials?: string;
}
