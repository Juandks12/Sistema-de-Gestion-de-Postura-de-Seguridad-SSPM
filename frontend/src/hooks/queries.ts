import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type {
  Asset,
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
  assets: ['assets'] as const,
  findings: (f: FindingsFilter) => ['findings', f] as const,
  scans: (f: ScansFilter) => ['scans', f] as const,
  users: ['users'] as const,
  organization: ['organization'] as const,
};

export function useOverview() {
  return useQuery({ queryKey: keys.overview, queryFn: () => api<Overview>('/dashboard/overview'), refetchInterval: 15000 });
}

export function useOrgHistory(days = 30) {
  return useQuery({ queryKey: keys.history(days), queryFn: () => api<OrgHistory>(`/dashboard/history${qs({ days })}`) });
}

export function useDashboardAssets() {
  return useQuery({ queryKey: keys.dashboardAssets, queryFn: () => api<{ items: DashboardAsset[]; total: number }>('/dashboard/assets'), refetchInterval: 15000 });
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
