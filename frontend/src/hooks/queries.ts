import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type {
  AlertChannel,
  AlertChannelType,
  AlertItem,
  AlertsSummary,
  AlertType,
  Asset,
  AssetVerification,
  DeliveryResult,
  DiscoveredHosts,
  ImportDiscoveredResult,
  MonitoringFrequency,
  MonitoringStatus,
  ReportRecord,
  AssetDashboard,
  DashboardAsset,
  AuthResponse,
  Finding,
  FindingCategory,
  FindingStatus,
  OrgHistory,
  OrgUser,
  Organization,
  Overview,
  Paginated,
  Scan,
  ScanStatus,
  ScanType,
  Severity,
  UserRole,
} from '@/lib/types';

export const keys = {
  overview: ['dashboard', 'overview'] as const,
  history: (days: number) => ['dashboard', 'history', days] as const,
  dashboardAssets: ['dashboard', 'assets'] as const,
  dashboardAsset: (id: string) => ['dashboard', 'asset', id] as const,
  verification: (id: string) => ['assets', id, 'verification'] as const,
  discovered: (id: string) => ['assets', id, 'discovered-hosts'] as const,
  assets: ['assets'] as const,
  findings: (f: FindingsFilter) => ['findings', f] as const,
  scans: (f: ScansFilter) => ['scans', f] as const,
  users: ['users'] as const,
  organization: ['organization'] as const,
  alerts: (f: AlertsFilter) => ['alerts', 'list', f] as const,
  alertsSummary: ['alerts', 'summary'] as const,
  alertChannels: ['alert-channels'] as const,
  monitoring: ['monitoring'] as const,
  reports: ['reports'] as const,
};

export function useOverview() {
  return useQuery({ queryKey: keys.overview, queryFn: () => api<Overview>('/dashboard/overview'), refetchInterval: 15000 });
}

export function useOrgHistory(days = 30) {
  return useQuery({ queryKey: keys.history(days), queryFn: () => api<OrgHistory>(`/dashboard/history${qs({ days })}`) });
}

export function useDashboardAssets() {
  return useQuery({
    queryKey: keys.dashboardAssets,
    queryFn: () => api<{ items: DashboardAsset[]; total: number; verificationRequired: boolean }>('/dashboard/assets'),
    refetchInterval: 15000,
  });
}

export function useDashboardAsset(id: string) {
  return useQuery({ queryKey: keys.dashboardAsset(id), queryFn: () => api<AssetDashboard>(`/dashboard/assets/${id}`), refetchInterval: 10000 });
}

export interface FindingsFilter {
  assetId?: string;
  severity?: Severity | '';
  status?: FindingStatus | '';
  category?: FindingCategory | '';
  page?: number;
  pageSize?: number;
}

export function useFindings(filter: FindingsFilter) {
  return useQuery({ queryKey: keys.findings(filter), queryFn: () => api<Paginated<Finding>>(`/findings${qs({ ...filter, pageSize: filter.pageSize ?? 25 })}`), placeholderData: (prev) => prev });
}

export interface ScansFilter {
  assetId?: string;
  status?: ScanStatus | '';
  type?: ScanType | '';
  page?: number;
}

export function useScans(filter: ScansFilter) {
  return useQuery({
    queryKey: keys.scans(filter),
    queryFn: () => api<Paginated<Scan>>(`/scans${qs({ ...filter, pageSize: 25 })}`),
    placeholderData: (prev) => prev,
    refetchInterval: (q) => (q.state.data?.items.some((s) => s.status === 'PENDING' || s.status === 'RUNNING') ? 4000 : 20000),
  });
}

/** Invalida todo lo que depende de escaneos y hallazgos. */
function useInvalidateAll() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ['dashboard'] });
    void qc.invalidateQueries({ queryKey: ['findings'] });
    void qc.invalidateQueries({ queryKey: ['scans'] });
    void qc.invalidateQueries({ queryKey: ['assets'] });
    void qc.invalidateQueries({ queryKey: ['alerts'] });
    void qc.invalidateQueries({ queryKey: keys.monitoring });
  };
}

export function useCreateAsset() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (input: { value: string; name?: string; description?: string; authorizationConfirmed: true }) => api<Asset>('/assets', { method: 'POST', json: input }),
    onSuccess: invalidate,
  });
}

export function useUpdateAsset() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: ({ id, ...input }: { id: string; name?: string; description?: string; isActive?: boolean }) => api<Asset>(`/assets/${id}`, { method: 'PATCH', json: input }),
    onSuccess: invalidate,
  });
}

export function useDeleteAsset() {
  const invalidate = useInvalidateAll();
  return useMutation({ mutationFn: (id: string) => api<void>(`/assets/${id}`, { method: 'DELETE' }), onSuccess: invalidate });
}

export interface AuditResult {
  queued: Scan[];
  skipped: Array<{ type: ScanType; reason: string }>;
}

/** Encola un tipo de escaneo concreto o, sin `type`, la auditoría completa. */
export function useRequestScan() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: async ({ assetId, type }: { assetId: string; type?: ScanType }): Promise<AuditResult> => {
      if (type) {
        const scan = await api<Scan>(`/assets/${assetId}/scans`, { method: 'POST', json: { type } });
        return { queued: [scan], skipped: [] };
      }
      return api<AuditResult>(`/assets/${assetId}/scans/all`, { method: 'POST' });
    },
    onSuccess: invalidate,
  });
}

export function useCancelScan() {
  const invalidate = useInvalidateAll();
  return useMutation({ mutationFn: (id: string) => api<Scan>(`/scans/${id}/cancel`, { method: 'POST' }), onSuccess: invalidate });
}

export function useReviewFinding() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: ({ id, status, note }: { id: string; status: 'OPEN' | 'ACCEPTED' | 'FALSE_POSITIVE'; note?: string }) => api<Finding>(`/findings/${id}`, { method: 'PATCH', json: { status, note } }),
    onSuccess: invalidate,
  });
}

export function useUsers(enabled = true) {
  return useQuery({ queryKey: keys.users, queryFn: () => api<OrgUser[]>('/users'), enabled });
}

export function useOrganization() {
  return useQuery({ queryKey: keys.organization, queryFn: () => api<Organization>('/organizations/me') });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { fullName: string; email: string; password: string; role: UserRole }) => api<OrgUser>('/users', { method: 'POST', json: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.users }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...input }: { id: string; role?: UserRole; isActive?: boolean }) => api<OrgUser>(`/users/${id}`, { method: 'PATCH', json: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.users }),
  });
}

export function useResetUserPassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, newPassword }: { id: string; newPassword: string }) => api<OrgUser>(`/users/${id}/reset-password`, { method: 'POST', json: { newPassword } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.users }),
  });
}

export function useChangeOwnPassword() {
  return useMutation({
    mutationFn: (input: { currentPassword: string; newPassword: string }) => api<AuthResponse>('/auth/me/password', { method: 'PATCH', json: input }),
  });
}

// ------------------------------------------------------------------ alertas

export interface AlertsFilter {
  acknowledged?: 'true' | 'false' | '';
  severity?: Severity | '';
  type?: AlertType | '';
  page?: number;
}

export function useAlerts(filter: AlertsFilter) {
  return useQuery({
    queryKey: keys.alerts(filter),
    queryFn: () => api<Paginated<AlertItem>>(`/alerts${qs({ ...filter, pageSize: 20 })}`),
    placeholderData: (prev) => prev,
    refetchInterval: 30000,
  });
}

export function useAlertsSummary() {
  return useQuery({ queryKey: keys.alertsSummary, queryFn: () => api<AlertsSummary>('/alerts/summary'), refetchInterval: 30000 });
}

export function useAcknowledgeAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<AlertItem>(`/alerts/${id}/acknowledge`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  });
}

export function useAcknowledgeAllAlerts() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<{ acknowledged: number }>('/alerts/acknowledge-all', { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  });
}

export function useAlertChannels(enabled = true) {
  return useQuery({
    queryKey: keys.alertChannels,
    queryFn: () => api<{ items: AlertChannel[]; emailEnabled: boolean }>('/alerts/channels'),
    enabled,
  });
}

export interface ChannelInput {
  type: AlertChannelType;
  name: string;
  target: string;
  minSeverity: Severity;
}

export function useCreateChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: ChannelInput) => api<AlertChannel>('/alerts/channels', { method: 'POST', json: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.alertChannels }),
  });
}

export function useUpdateChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...input }: { id: string; name?: string; target?: string; minSeverity?: Severity; isActive?: boolean }) =>
      api<AlertChannel>(`/alerts/channels/${id}`, { method: 'PATCH', json: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.alertChannels }),
  });
}

export function useDeleteChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/alerts/channels/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.alertChannels }),
  });
}

export function useTestChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<DeliveryResult>(`/alerts/channels/${id}/test`, { method: 'POST' }),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.alertChannels }),
  });
}

// ------------------------------------------------------- monitoreo continuo

export function useMonitoring() {
  return useQuery({ queryKey: keys.monitoring, queryFn: () => api<MonitoringStatus>('/monitoring') });
}

export function useUpdateMonitoring() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (frequency: MonitoringFrequency) => api<MonitoringStatus>('/monitoring', { method: 'PATCH', json: { frequency } }),
    onSuccess: (data) => qc.setQueryData(keys.monitoring, data),
  });
}

// ----------------------------------------------------------------- reportes

export function useReports() {
  return useQuery({ queryKey: keys.reports, queryFn: () => api<{ items: ReportRecord[] }>('/reports') });
}

// ------------------------------------------------- verificación de activos

export function useAssetVerification(id: string, enabled = true) {
  return useQuery({ queryKey: keys.verification(id), queryFn: () => api<AssetVerification>(`/assets/${id}/verification`), enabled });
}

export function useVerifyAsset() {
  const invalidate = useInvalidateAll();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, method }: { id: string; method?: 'DNS_TXT' | 'HTTP_FILE' }) =>
      api<AssetVerification>(`/assets/${id}/verify`, { method: 'POST', json: method ? { method } : {} }),
    onSuccess: (data, { id }) => {
      qc.setQueryData(keys.verification(id), data);
      invalidate();
    },
  });
}

export function useDiscoveredHosts(assetId: string, enabled = true) {
  return useQuery({
    queryKey: keys.discovered(assetId),
    queryFn: () => api<DiscoveredHosts>(`/assets/${assetId}/discovered-hosts`),
    enabled,
  });
}

export function useSetDiscoveredHostIgnored() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ignored }: { id: string; assetId: string; ignored: boolean }) =>
      api<{ id: string; hostname: string; ignored: boolean }>(`/discovered-hosts/${id}`, { method: 'PATCH', json: { ignored } }),
    onSuccess: (_data, { assetId }) => qc.invalidateQueries({ queryKey: keys.discovered(assetId) }),
  });
}

export function useImportDiscoveredHosts() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (ids: string[]) =>
      api<ImportDiscoveredResult>('/discovered-hosts/import', { method: 'POST', json: { ids, authorizationConfirmed: true } }),
    onSuccess: invalidate,
  });
}
