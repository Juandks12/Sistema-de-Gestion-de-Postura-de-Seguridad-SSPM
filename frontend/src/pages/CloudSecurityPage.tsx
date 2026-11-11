import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Cloud,
  Copy,
  Database,
  ExternalLink,
  Layers,
  Play,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
} from 'lucide-react';
import { Fragment, useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { GradeBadge, SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardBody } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input, Label, Select } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import {
  useCloudAccounts,
  useCloudOnboardingTemplate,
  useCloudResources,
  useCloudSummary,
  useCreateCloudAccount,
  useCspmRules,
  useDeleteCloudAccount,
  useScanCloudAccount,
  useTestCloudConnection,
  useVerifyCloudAccount,
} from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import {
  CATEGORY_LABEL,
  CLOUD_RESOURCE_TYPE_LABEL,
  cvss,
  timeAgo,
} from '@/lib/format';
import type {
  CloudAccountItem,
  CloudAuditResponse,
  CloudAuthType,
  CloudProvider,
  CloudResourceType,
  Grade,
} from '@/lib/types';

type CloudTab = 'accounts' | 'inventory' | 'rules';

const RESOURCE_TYPES: CloudResourceType[] = [
  'AWS_S3_BUCKET',
  'AWS_IAM_USER',
  'AWS_IAM_ROLE',
  'AWS_SECURITY_GROUP',
  'AWS_EC2_INSTANCE',
  'AWS_RDS_INSTANCE',
  'AWS_CLOUDTRAIL',
  'AWS_VPC',
  'AZURE_STORAGE_ACCOUNT',
  'AZURE_BLOB_CONTAINER',
  'AZURE_NSG',
  'AZURE_VM',
  'AZURE_SQL_DATABASE',
  'AZURE_ACTIVITY_LOG',
  'AZURE_VNET',
  'GCP_STORAGE_BUCKET',
  'GCP_SERVICE_ACCOUNT',
  'GCP_FIREWALL_RULE',
  'GCP_COMPUTE_INSTANCE',
  'GCP_SQL_INSTANCE',
  'GCP_LOGGING_SINK',
  'OTHER',
];

export function CloudSecurityPage() {
  const { canEdit, hasRole } = useAuth();
  const isAdmin = hasRole('ADMIN');
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const activeTab = (params.get('tab') as CloudTab) || 'accounts';
  const selectedAccountFilter = params.get('cloudAccountId') ?? '';
  const selectedProviderFilter = (params.get('provider') as CloudProvider | '') ?? '';
  const selectedResourceType = (params.get('resourceType') as CloudResourceType | '') ?? '';
  const findingsFilter = params.get('hasActiveFindings') ?? '';

  const [searchText, setSearchText] = useState('');
  const [connectModalOpen, setConnectModalOpen] = useState(false);
  const [expandedResource, setExpandedResource] = useState<string | null>(null);
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [lastAuditResult, setLastAuditResult] = useState<CloudAuditResponse | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [scanningAccountId, setScanningAccountId] = useState<string | null>(null);

  const summaryQ = useCloudSummary();
  const accountsQ = useCloudAccounts();
  const resourcesQ = useCloudResources({
    provider: selectedProviderFilter || undefined,
    cloudAccountId: selectedAccountFilter || undefined,
    resourceType: selectedResourceType || undefined,
    hasActiveFindings:
      findingsFilter === 'true'
        ? true
        : findingsFilter === 'false'
          ? false
          : undefined,
    search: searchText.trim() || undefined,
  });
  const rulesQ = useCspmRules(selectedProviderFilter || undefined);

  const scanMutation = useScanCloudAccount();
  const verifyMutation = useVerifyCloudAccount();
  const deleteMutation = useDeleteCloudAccount();

  const setTab = (tab: CloudTab, extra?: Record<string, string>) => {
    const next = new URLSearchParams(params);
    next.set('tab', tab);
    if (extra) {
      for (const [k, v] of Object.entries(extra)) {
        if (v) next.set(k, v);
        else next.delete(k);
      }
    }
    setParams(next, { replace: true });
  };

  const updateParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  const handleRunAudit = async (account: CloudAccountItem, simulate?: boolean) => {
    setActionError(null);
    setScanningAccountId(account.id);
    try {
      const res = await scanMutation.mutateAsync({
        accountId: account.id,
        simulate,
      });
      setLastAuditResult(res);
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err.message
          : 'No se pudo completar la auditoría CSPM de la cuenta cloud.',
      );
    } finally {
      setScanningAccountId(null);
    }
  };

  const handleVerifyAccount = async (accountId: string) => {
    setActionError(null);
    try {
      await verifyMutation.mutateAsync(accountId);
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err.message
          : 'No se pudo verificar la cuenta cloud.',
      );
    }
  };

  const handleDeleteAccount = async (account: CloudAccountItem) => {
    if (
      !window.confirm(
        `¿Seguro que deseas desconectar y eliminar la cuenta ${account.name} (${account.accountOrSubscriptionId})?`,
      )
    ) {
      return;
    }
    setActionError(null);
    try {
      await deleteMutation.mutateAsync(account.id);
      if (lastAuditResult?.account.id === account.id) {
        setLastAuditResult(null);
      }
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err.message
          : 'No se pudo eliminar la cuenta cloud.',
      );
    }
  };

  const summary = summaryQ.data;
  const accounts = accountsQ.data ?? [];
  const resources = resourcesQ.data ?? [];
  const rules = rulesQ.data ?? [];

  return (
    <>
      <PageHeader
        title="Seguridad Cloud (CSPM)"
        description="Gestión centralizada de postura de seguridad multi-nube para AWS, Azure y Google Cloud Platform (GCP): inventario agentless, evaluación de 36 reglas y remediación IaC/CLI."
        actions={
          canEdit ? (
            <Button
              icon={<Plus className="size-4" />}
              onClick={() => setConnectModalOpen(true)}
            >
              Conectar cuenta Cloud
            </Button>
          ) : null
        }
      />

      {/* Resumen Ejecutivo CSPM */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-border bg-surface p-4 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Cuentas Conectadas</span>
            <Cloud className="size-4 text-accent" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-ink tabular">
              {summary?.accounts.total ?? 0}
            </span>
            <span className="text-xs text-muted">
              ({summary?.accounts.byProvider.AWS ?? 0} AWS · {summary?.accounts.byProvider.AZURE ?? 0} Azure · {summary?.accounts.byProvider.GCP ?? 0} GCP)
            </span>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setTab('inventory', { hasActiveFindings: '' })}
          className="rounded-xl border border-border bg-surface p-4 text-left transition hover:border-accent/50 shadow-xs"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Inventario de Recursos</span>
            <Layers className="size-4 text-accent" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-ink tabular">
              {summary?.resources.total ?? 0}
            </span>
            <span className="text-xs text-muted">
              {summary?.resources.clean ?? 0} seguros
            </span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setTab('inventory', { hasActiveFindings: 'true' })}
          className="rounded-xl border border-border bg-surface p-4 text-left transition hover:border-warning/60 shadow-xs"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Recursos en Riesgo</span>
            <Server className="size-4 text-warning" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#8a5b00] dark:text-warning tabular">
              {summary?.resources.withFindings ?? 0}
            </span>
            <span className="text-xs text-muted">con hallazgos activos</span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => navigate('/findings?domain=cloud&status=OPEN')}
          className="rounded-xl border border-border bg-surface p-4 text-left transition hover:border-critical/60 shadow-xs"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Hallazgos Cloud Abiertos</span>
            <ShieldAlert className="size-4 text-critical" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-critical tabular">
              {summary?.findings.totalOpen ?? 0}
            </span>
            <span className="text-xs text-muted">
              {summary?.findings.bySeverity.CRITICAL ?? 0} crít. · {summary?.findings.bySeverity.HIGH ?? 0} altos
            </span>
          </div>
        </button>
      </div>

      {actionError ? (
        <Alert kind="error" className="mb-4">
          {actionError}
        </Alert>
      ) : null}

      {lastAuditResult ? (
        <div className="mb-6 rounded-xl border border-accent/30 bg-accent/5 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              {lastAuditResult.stats.grade ? (
                <GradeBadge grade={lastAuditResult.stats.grade as Grade} size="md" />
              ) : null}
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-ink">
                    Auditoría CSPM completada: {lastAuditResult.account.name}
                  </h3>
                  {lastAuditResult.simulated ? (
                    <span className="rounded-md bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-600 dark:text-amber-400">
                      Inventario Benchmark / Sandbox
                    </span>
                  ) : null}
                </div>
                <p className="text-xs text-ink-2 mt-0.5">
                  {lastAuditResult.evaluatedRulesCount} reglas evaluadas en {lastAuditResult.durationMs} ms ·{' '}
                  <strong>{lastAuditResult.stats.resourcesDiscovered}</strong> recursos descubiertos ·{' '}
                  <strong>{lastAuditResult.stats.activeFindings}</strong> hallazgos activos (
                  {lastAuditResult.stats.findingsCreated} nuevos,{' '}
                  {lastAuditResult.stats.findingsResolved} auto-resueltos) · Score del activo:{' '}
                  <strong>{lastAuditResult.stats.score ?? '—'}/100</strong>
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="secondary"
                onClick={() =>
                  setTab('inventory', { cloudAccountId: lastAuditResult.account.id })
                }
              >
                Ver recursos ({lastAuditResult.stats.resourcesDiscovered})
              </Button>
              <Button
                size="sm"
                onClick={() =>
                  navigate(
                    `/findings?domain=cloud&cloudAccountId=${lastAuditResult.account.id}&status=OPEN`,
                  )
                }
              >
                Gestionar hallazgos ({lastAuditResult.stats.activeFindings})
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      {/* Pestañas de navegación */}
      <div className="mb-5 flex flex-wrap gap-2 border-b border-line pb-2">
        <button
          type="button"
          onClick={() => setTab('accounts')}
          className={cn(
            'inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors',
            activeTab === 'accounts'
              ? 'bg-accent text-white shadow-xs'
              : 'text-ink-2 hover:bg-surface-2 hover:text-ink',
          )}
        >
          <Cloud className="size-4" />
          Cuentas Conectadas ({accounts.length})
        </button>

        <button
          type="button"
          onClick={() => setTab('inventory')}
          className={cn(
            'inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors',
            activeTab === 'inventory'
              ? 'bg-accent text-white shadow-xs'
              : 'text-ink-2 hover:bg-surface-2 hover:text-ink',
          )}
        >
          <Database className="size-4" />
          Inventario de Recursos ({summary?.resources.total ?? resources.length})
        </button>

        <button
          type="button"
          onClick={() => setTab('rules')}
          className={cn(
            'inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors',
            activeTab === 'rules'
              ? 'bg-accent text-white shadow-xs'
              : 'text-ink-2 hover:bg-surface-2 hover:text-ink',
          )}
        >
          <ShieldCheck className="size-4" />
          Catálogo de Controles CSPM (31)
        </button>
      </div>

      {/* TAB 1: CUENTAS CONECTADAS */}
      {activeTab === 'accounts' ? (
        accountsQ.isPending ? (
          <div className="grid gap-4 md:grid-cols-2">
            <Skeleton className="h-48" />
            <Skeleton className="h-48" />
          </div>
        ) : accounts.length === 0 ? (
          <Card>
            <EmptyState
              icon={Cloud}
              title="Sin cuentas de AWS, Azure o GCP conectadas"
              description="Conecta una cuenta de Amazon Web Services (mediante IAM Cross-Account Role), una suscripción de Microsoft Azure (mediante Service Principal), un proyecto de Google Cloud Platform (mediante Service Account Key), o lanza una cuenta Sandbox de demostración en 1 clic."
              action={
                canEdit ? (
                  <Button
                    icon={<Plus className="size-4" />}
                    onClick={() => setConnectModalOpen(true)}
                  >
                    Conectar primera cuenta Cloud
                  </Button>
                ) : null
              }
            />
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {accounts.map((acc) => {
              const isScanning = scanningAccountId === acc.id;
              return (
                <Card key={acc.id}>
                  <CardBody className="flex flex-col justify-between gap-4">
                    <div>
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-center gap-2.5">
                          <ProviderBadge provider={acc.provider} />
                          <div>
                            <h3 className="font-semibold text-base text-ink">
                              {acc.name}
                            </h3>
                            <p className="font-mono text-xs text-muted">
                              {acc.provider === 'AWS'
                                ? 'Account ID: '
                                : acc.provider === 'AZURE'
                                  ? 'Subscription ID: '
                                  : 'Project ID: '}
                              {acc.accountOrSubscriptionId}
                            </p>
                            {acc.gcpClientEmail ? (
                              <p className="font-mono text-[11px] text-muted truncate max-w-[280px]">
                                {acc.gcpClientEmail}
                              </p>
                            ) : null}
                          </div>
                        </div>
                        <AccountStatusBadge status={acc.status} />
                      </div>

                      <dl className="mt-4 grid grid-cols-2 gap-3 rounded-lg bg-surface-2/60 p-3 text-xs">
                        <div>
                          <dt className="text-muted">Autenticación</dt>
                          <dd className="font-medium text-ink mt-0.5">
                            {acc.authType === 'ROLE_ARN'
                              ? 'IAM Cross-Account Role'
                              : acc.authType === 'ACCESS_KEYS'
                                ? 'IAM Access Keys'
                                : acc.authType === 'SERVICE_ACCOUNT_KEY'
                                  ? 'GCP Service Account Key'
                                  : 'Entra ID Service Principal'}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-muted">Regiones monitoreadas</dt>
                          <dd className="font-medium text-ink mt-0.5 truncate">
                            {acc.monitoredRegions.join(', ') || 'Global'}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-muted">Recursos descubiertos</dt>
                          <dd className="font-semibold text-ink mt-0.5 tabular">
                            {acc.resourceCount} recursos
                          </dd>
                        </div>
                        <div>
                          <dt className="text-muted">Hallazgos abiertos</dt>
                          <dd
                            className={cn(
                              'font-semibold mt-0.5 tabular',
                              acc.failingFindingCount > 0
                                ? 'text-critical'
                                : 'text-good-text',
                            )}
                          >
                            {acc.failingFindingCount} hallazgos
                          </dd>
                        </div>
                      </dl>

                      {acc.lastAuditError ? (
                        <p className="mt-3 rounded-lg border border-critical/25 bg-critical/5 px-3 py-2 text-xs text-critical">
                          <strong>Detalle de conexión:</strong> {acc.lastAuditError}
                        </p>
                      ) : null}

                      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
                        <span>
                          Última auditoría:{' '}
                          {acc.lastAuditedAt ? timeAgo(acc.lastAuditedAt) : 'Pendiente de primera ejecución'}
                        </span>
                        {acc.assetId ? (
                          <Link
                            to={`/assets/${acc.assetId}`}
                            className="inline-flex items-center gap-1 font-medium text-accent hover:underline"
                          >
                            Ver ficha de activo <ExternalLink className="size-3" />
                          </Link>
                        ) : null}
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-3">
                      <div className="flex flex-wrap gap-2">
                        {canEdit ? (
                          <>
                            <Button
                              size="sm"
                              icon={<Play className="size-3.5" />}
                              loading={isScanning}
                              onClick={() => handleRunAudit(acc)}
                            >
                              Auditar ahora
                            </Button>
                            <Button
                              size="sm"
                              variant="secondary"
                              icon={<Sparkles className="size-3.5" />}
                              disabled={isScanning}
                              onClick={() => handleRunAudit(acc, true)}
                              title="Ejecuta la evaluación CSPM con inventario de referencia sin requerir llamadas externas"
                            >
                              Simular auditoría
                            </Button>
                            <Button
                              size="sm"
                              variant="secondary"
                              icon={<RefreshCw className="size-3.5" />}
                              loading={verifyMutation.isPending}
                              onClick={() => handleVerifyAccount(acc.id)}
                            >
                              Verificar
                            </Button>
                          </>
                        ) : null}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            setTab('inventory', { cloudAccountId: acc.id })
                          }
                        >
                          Recursos ({acc.resourceCount})
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            navigate(
                              `/findings?domain=cloud&cloudAccountId=${acc.id}&status=OPEN`,
                            )
                          }
                        >
                          Hallazgos ({acc.failingFindingCount})
                        </Button>
                      </div>

                      {isAdmin ? (
                        <button
                          type="button"
                          onClick={() => handleDeleteAccount(acc)}
                          className="rounded-md p-1.5 text-muted hover:bg-critical/10 hover:text-critical"
                          title="Eliminar cuenta cloud"
                        >
                          <Trash2 className="size-4" />
                        </button>
                      ) : null}
                    </div>
                  </CardBody>
                </Card>
              );
            })}
          </div>
        )
      ) : null}

      {/* TAB 2: INVENTARIO DE RECURSOS CLOUD */}
      {activeTab === 'inventory' ? (
        <>
          <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <div className="lg:col-span-2">
              <Label htmlFor="res-search">Buscar recurso (Nombre, ARN / Resource ID o Región)</Label>
              <div className="relative">
                <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted" />
                <Input
                  id="res-search"
                  className="pl-9"
                  placeholder="Ej.arn:aws:s3:::, stprod, eastus..."
                  value={searchText}
                  onChange={(e) => setSearchText(e.target.value)}
                />
              </div>
            </div>

            <div>
              <Label htmlFor="res-provider">Proveedor</Label>
              <Select
                id="res-provider"
                value={selectedProviderFilter}
                onChange={(e) => updateParam('provider', e.target.value)}
              >
                <option value="">Todas las nubes (AWS, Azure, GCP)</option>
                <option value="AWS">Amazon Web Services (AWS)</option>
                <option value="AZURE">Microsoft Azure</option>
                <option value="GCP">Google Cloud Platform (GCP)</option>
              </Select>
            </div>

            <div>
              <Label htmlFor="res-type">Tipo de Recurso</Label>
              <Select
                id="res-type"
                value={selectedResourceType}
                onChange={(e) => updateParam('resourceType', e.target.value)}
              >
                <option value="">Todos los tipos</option>
                {RESOURCE_TYPES.map((rt) => (
                  <option key={rt} value={rt}>
                    {CLOUD_RESOURCE_TYPE_LABEL[rt]}
                  </option>
                ))}
              </Select>
            </div>

            <div>
              <Label htmlFor="res-status">Estado de Postura</Label>
              <Select
                id="res-status"
                value={findingsFilter}
                onChange={(e) => updateParam('hasActiveFindings', e.target.value)}
              >
                <option value="">Todos los recursos</option>
                <option value="true">Con hallazgos activos</option>
                <option value="false">Seguros (sin hallazgos)</option>
              </Select>
            </div>
          </div>

          {selectedAccountFilter ? (
            <Alert kind="info" className="mb-4">
              Filtrando recursos de una cuenta específica.{' '}
              <button
                type="button"
                className="font-semibold underline"
                onClick={() => updateParam('cloudAccountId', '')}
              >
                Mostrar todas las cuentas
              </button>
            </Alert>
          ) : null}

          <Card>
            {resourcesQ.isPending ? (
              <div className="space-y-3 p-5">
                {[0, 1, 2, 3].map((i) => (
                  <Skeleton key={i} className="h-10" />
                ))}
              </div>
            ) : resources.length === 0 ? (
              <EmptyState
                icon={Database}
                title="No se encontraron recursos cloud"
                description="Ejecuta una auditoría sobre tus cuentas conectadas (AWS, Azure o GCP) para poblar el inventario de recursos."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th className="w-8" />
                    <Th>Proveedor</Th>
                    <Th>Recurso / Identificador Nativo</Th>
                    <Th className="hidden md:table-cell">Tipo</Th>
                    <Th className="hidden lg:table-cell">Región</Th>
                    <Th className="hidden xl:table-cell">Cuenta</Th>
                    <Th>Postura</Th>
                  </tr>
                </thead>
                <tbody>
                  {resources.map((res) => {
                    const isOpen = expandedResource === res.id;
                    const activeFindings = res.findings ?? [];
                    return (
                      <Fragment key={res.id}>
                        <tr
                          className="cursor-pointer hover:bg-surface-2/60"
                          onClick={() =>
                            setExpandedResource(isOpen ? null : res.id)
                          }
                        >
                          <Td className="text-muted">
                            {isOpen ? (
                              <ChevronDown className="size-4" />
                            ) : (
                              <ChevronRight className="size-4" />
                            )}
                          </Td>
                          <Td>
                            <ProviderBadge provider={res.provider} />
                          </Td>
                          <Td>
                            <p className="font-medium text-ink">{res.name}</p>
                            <p className="font-mono text-[11px] text-muted truncate max-w-md">
                              {res.nativeId}
                            </p>
                          </Td>
                          <Td className="hidden md:table-cell text-xs text-ink-2">
                            {CLOUD_RESOURCE_TYPE_LABEL[res.resourceType]}
                          </Td>
                          <Td className="hidden lg:table-cell font-mono text-xs text-ink-2">
                            {res.region ?? 'global'}
                          </Td>
                          <Td className="hidden xl:table-cell text-xs text-ink-2">
                            {res.cloudAccount?.name ?? '—'}
                          </Td>
                          <Td>
                            {res.hasActiveFindings ? (
                              <span className="inline-flex items-center gap-1 rounded-full bg-critical/15 px-2.5 py-0.5 text-xs font-semibold text-critical">
                                <AlertTriangle className="size-3.5" />
                                {activeFindings.length || 1} hallazgo(s)
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 rounded-full bg-good/15 px-2.5 py-0.5 text-xs font-semibold text-good-text">
                                <CheckCircle2 className="size-3.5" />
                                Cumple
                              </span>
                            )}
                          </Td>
                        </tr>
                        {isOpen ? (
                          <tr className="bg-surface-2/40">
                            <td colSpan={7} className="border-b border-line px-5 py-4">
                              <div className="grid gap-4 lg:grid-cols-2">
                                <div>
                                  <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">
                                    Configuración recolectada (Metadatos Cloud)
                                  </h4>
                                  <pre className="mt-2 max-h-56 overflow-auto rounded-lg border border-border bg-[#18181b] p-3 font-mono text-xs text-zinc-100">
                                    {JSON.stringify(res.configuration ?? {}, null, 2)}
                                  </pre>
                                  {res.tags && Object.keys(res.tags).length > 0 ? (
                                    <div className="mt-3 flex flex-wrap gap-1.5">
                                      {Object.entries(res.tags).map(([k, v]) => (
                                        <span
                                          key={k}
                                          className="rounded-md border border-border bg-surface px-2 py-0.5 font-mono text-[11px] text-ink-2"
                                        >
                                          {k}: {v}
                                        </span>
                                      ))}
                                    </div>
                                  ) : null}
                                </div>

                                <div>
                                  <div className="flex items-center justify-between">
                                    <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">
                                      Hallazgos de Seguridad en este Recurso ({activeFindings.length})
                                    </h4>
                                    {activeFindings.length > 0 ? (
                                      <Link
                                        to={`/findings?domain=cloud&cloudAccountId=${res.cloudAccountId}&status=OPEN`}
                                        className="text-xs font-medium text-accent hover:underline"
                                      >
                                        Ir a gestión y remediación →
                                      </Link>
                                    ) : null}
                                  </div>
                                  {activeFindings.length === 0 ? (
                                    <p className="mt-2 text-xs text-good-text">
                                      Este recurso no presenta incumplimientos activos frente al catálogo CSPM.
                                    </p>
                                  ) : (
                                    <ul className="mt-2 divide-y divide-line rounded-lg border border-border bg-surface">
                                      {activeFindings.map((f) => (
                                        <li
                                          key={f.id}
                                          className="flex items-center justify-between gap-2 px-3 py-2 text-xs"
                                        >
                                          <div className="flex items-center gap-2 min-w-0">
                                            <SeverityBadge severity={f.severity} compact />
                                            <span className="font-mono text-muted shrink-0">
                                              {f.ruleId}
                                            </span>
                                            <span className="truncate font-medium text-ink">
                                              {f.title}
                                            </span>
                                          </div>
                                          <Link
                                            to={`/findings?domain=cloud&cloudAccountId=${res.cloudAccountId}&status=OPEN`}
                                            className="shrink-0 font-medium text-accent hover:underline"
                                          >
                                            Remediar
                                          </Link>
                                        </li>
                                      ))}
                                    </ul>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    );
                  })}
                </tbody>
              </Table>
            )}
          </Card>
        </>
      ) : null}

      {/* TAB 3: CATÁLOGO DE 36 REGLAS CSPM */}
      {activeTab === 'rules' ? (
        <>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap gap-2">
              {(['', 'AWS', 'AZURE', 'GCP'] as const).map((prov) => (
                <button
                  key={prov || 'ALL'}
                  type="button"
                  onClick={() => updateParam('provider', prov)}
                  className={cn(
                    'rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors',
                    selectedProviderFilter === prov
                      ? 'border-accent bg-accent/10 text-accent-strong'
                      : 'border-border bg-surface text-ink-2 hover:bg-surface-2',
                  )}
                >
                  {prov === ''
                    ? 'Todos los proveedores (36)'
                    : prov === 'AWS'
                      ? 'Amazon Web Services (19)'
                      : prov === 'AZURE'
                        ? 'Microsoft Azure (12)'
                        : 'Google Cloud Platform (5)'}
                </button>
              ))}
            </div>
          </div>

          <Card>
            {rulesQ.isPending ? (
              <div className="space-y-3 p-5">
                {[0, 1, 2, 3].map((i) => (
                  <Skeleton key={i} className="h-10" />
                ))}
              </div>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th className="w-8" />
                    <Th>Proveedor</Th>
                    <Th>Código</Th>
                    <Th>Severidad</Th>
                    <Th>Control de Postura</Th>
                    <Th className="hidden md:table-cell">Dominio</Th>
                    <Th className="hidden lg:table-cell">CVSS</Th>
                    <Th className="hidden xl:table-cell">Marcos Normativos</Th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => {
                    const isOpen = expandedRule === r.ruleId;
                    return (
                      <Fragment key={r.ruleId}>
                        <tr
                          className="cursor-pointer hover:bg-surface-2/60"
                          onClick={() =>
                            setExpandedRule(isOpen ? null : r.ruleId)
                          }
                        >
                          <Td className="text-muted">
                            {isOpen ? (
                              <ChevronDown className="size-4" />
                            ) : (
                              <ChevronRight className="size-4" />
                            )}
                          </Td>
                          <Td>
                            <ProviderBadge provider={r.provider} />
                          </Td>
                          <Td className="font-mono text-xs font-semibold text-ink">
                            {r.ruleId}
                          </Td>
                          <Td>
                            <SeverityBadge severity={r.severity} compact />
                          </Td>
                          <Td className="font-medium text-ink">{r.title}</Td>
                          <Td className="hidden md:table-cell text-xs text-ink-2">
                            {CATEGORY_LABEL[r.category]}
                          </Td>
                          <Td className="hidden lg:table-cell tabular text-xs text-ink-2">
                            {cvss(r.cvssScore)}
                          </Td>
                          <Td className="hidden xl:table-cell">
                            <div className="flex flex-wrap gap-1">
                              {r.complianceControlIds.map((cid) => (
                                <span
                                  key={cid}
                                  className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-ink-2"
                                >
                                  {cid}
                                </span>
                              ))}
                            </div>
                          </Td>
                        </tr>
                        {isOpen ? (
                          <tr className="bg-surface-2/40">
                            <td colSpan={8} className="border-b border-line px-5 py-4">
                              <p className="text-sm text-ink">{r.description}</p>
                              <p className="mt-2 text-xs text-ink-2">
                                <strong>Recomendación:</strong> {r.recommendation}
                              </p>
                              <div className="mt-3 grid gap-3 lg:grid-cols-2">
                                <div>
                                  <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-ink">
                                    <Terminal className="size-3.5 text-accent" />
                                    Remediación CLI ({r.provider === 'AWS' ? 'AWS CLI' : r.provider === 'AZURE' ? 'Azure CLI' : 'gcloud CLI'})
                                  </p>
                                  <pre className="overflow-x-auto rounded-lg border border-border bg-[#18181b] p-3 font-mono text-xs text-zinc-100 whitespace-pre-wrap">
                                    {r.remediationCli}
                                  </pre>
                                </div>
                                <div>
                                  <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-ink">
                                    <Layers className="size-3.5 text-accent" />
                                    Infraestructura como Código (Terraform)
                                  </p>
                                  <pre className="overflow-x-auto rounded-lg border border-border bg-[#18181b] p-3 font-mono text-xs text-zinc-100 whitespace-pre-wrap">
                                    {r.remediationIac}
                                  </pre>
                                </div>
                              </div>
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    );
                  })}
                </tbody>
              </Table>
            )}
          </Card>
        </>
      ) : null}

      {connectModalOpen ? (
        <ConnectCloudAccountModal
          onClose={() => setConnectModalOpen(false)}
          onCreated={(createdAccount) => {
            setConnectModalOpen(false);
            handleRunAudit(createdAccount);
          }}
        />
      ) : null}
    </>
  );
}

function ProviderBadge({ provider }: { provider: CloudProvider }) {
  if (provider === 'AWS') {
    return (
      <span className="inline-flex items-center rounded-md bg-amber-500/15 px-2 py-0.5 text-xs font-bold text-amber-600 dark:text-amber-400">
        AWS
      </span>
    );
  }
  if (provider === 'AZURE') {
    return (
      <span className="inline-flex items-center rounded-md bg-sky-500/15 px-2 py-0.5 text-xs font-bold text-sky-600 dark:text-sky-400">
        Azure
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded-md bg-emerald-500/15 px-2 py-0.5 text-xs font-bold text-emerald-600 dark:text-emerald-400">
      GCP
    </span>
  );
}

function AccountStatusBadge({ status }: { status: string }) {
  if (status === 'CONNECTED') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-good/15 px-2.5 py-0.5 text-xs font-semibold text-good-text">
        <CheckCircle2 className="size-3.5" /> Conectada
      </span>
    );
  }
  if (status === 'ERROR') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-critical/15 px-2.5 py-0.5 text-xs font-semibold text-critical">
        <AlertTriangle className="size-3.5" /> Error de acceso
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-surface-2 px-2.5 py-0.5 text-xs font-medium text-ink-2">
      Pendiente
    </span>
  );
}

function ConnectCloudAccountModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (account: CloudAccountItem) => void;
}) {
  const onboardingQ = useCloudOnboardingTemplate();
  const testMutation = useTestCloudConnection();
  const createMutation = useCreateCloudAccount();

  const [provider, setProvider] = useState<CloudProvider>('AWS');
  const [authType, setAuthType] = useState<CloudAuthType>('ROLE_ARN');
  const [name, setName] = useState('');
  const [accountOrSubscriptionId, setAccountOrSubscriptionId] = useState('');
  const [awsRoleArn, setAwsRoleArn] = useState('');
  const [awsAccessKeyId, setAwsAccessKeyId] = useState('');
  const [awsSecretAccessKey, setAwsSecretAccessKey] = useState('');
  const [azureTenantId, setAzureTenantId] = useState('');
  const [azureClientId, setAzureClientId] = useState('');
  const [azureClientSecret, setAzureClientSecret] = useState('');
  const [gcpClientEmail, setGcpClientEmail] = useState('');
  const [gcpPrivateKey, setGcpPrivateKey] = useState('');
  const [gcpServiceAccountJson, setGcpServiceAccountJson] = useState('');
  const [gcpSnippetType, setGcpSnippetType] = useState<'terraform' | 'cli'>('terraform');
  const [regionsText, setRegionsText] = useState('us-east-1, us-west-2');
  const [verifyOnCreate, setVerifyOnCreate] = useState(true);
  const [showTemplate, setShowTemplate] = useState(false);
  const [copiedCfn, setCopiedCfn] = useState(false);
  const [testFeedback, setTestFeedback] = useState<{
    valid: boolean;
    message: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const switchProvider = (next: CloudProvider) => {
    setProvider(next);
    setTestFeedback(null);
    setError(null);
    if (next === 'AWS') {
      setAuthType('ROLE_ARN');
      setRegionsText('us-east-1, us-west-2');
    } else if (next === 'AZURE') {
      setAuthType('SERVICE_PRINCIPAL');
      setRegionsText('eastus, westus2');
    } else {
      setAuthType('SERVICE_ACCOUNT_KEY');
      setRegionsText('us-central1, us-east1, global');
    }
  };

  const handleGcpJsonPaste = (val: string) => {
    setGcpServiceAccountJson(val);
    try {
      const parsed = JSON.parse(val);
      if (parsed.project_id) {
        setAccountOrSubscriptionId(parsed.project_id);
        if (!name) setName(`GCP ${parsed.project_id}`);
      }
      if (parsed.client_email) {
        setGcpClientEmail(parsed.client_email);
      }
      if (parsed.private_key) {
        setGcpPrivateKey(parsed.private_key);
      }
    } catch {
      // JSON aún no completo
    }
  };

  const loadSandboxPreset = () => {
    setError(null);
    setTestFeedback(null);
    setVerifyOnCreate(false);
    if (provider === 'AWS') {
      setName('AWS Producción (Sandbox Demo)');
      setAuthType('ROLE_ARN');
      setAccountOrSubscriptionId('000000000000');
      setAwsRoleArn('arn:aws:iam::000000000000:role/SSPM-Cloud-Auditor-Role');
      setRegionsText('us-east-1');
    } else if (provider === 'AZURE') {
      setName('Azure Corporativo (Sandbox Demo)');
      setAuthType('SERVICE_PRINCIPAL');
      setAccountOrSubscriptionId('00000000-0000-0000-0000-000000000000');
      setAzureTenantId('11111111-1111-1111-1111-111111111111');
      setAzureClientId('22222222-2222-2222-2222-222222222222');
      setAzureClientSecret('sandbox-demo-secret-value');
      setRegionsText('eastus');
    } else {
      setName('GCP Producción (Sandbox Demo)');
      setAuthType('SERVICE_ACCOUNT_KEY');
      setAccountOrSubscriptionId('sspm-enterprise-sandbox-demo');
      setGcpClientEmail('sspm-auditor@sspm-enterprise-sandbox-demo.iam.gserviceaccount.com');
      setGcpPrivateKey('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0demo...\n-----END RSA PRIVATE KEY-----');
      setGcpServiceAccountJson('{\n  "type": "service_account",\n  "project_id": "sspm-enterprise-sandbox-demo",\n  "client_email": "sspm-auditor@sspm-enterprise-sandbox-demo.iam.gserviceaccount.com"\n}');
      setRegionsText('us-central1, us-east1');
    }
  };

  const handleTestConnection = async () => {
    setError(null);
    setTestFeedback(null);
    try {
      const res = await testMutation.mutateAsync({
        provider,
        authType,
        accountOrSubscriptionId,
        awsRoleArn: awsRoleArn || undefined,
        awsExternalId: onboardingQ.data?.awsExternalId,
        awsAccessKeyId: awsAccessKeyId || undefined,
        awsSecretAccessKey: awsSecretAccessKey || undefined,
        azureTenantId: azureTenantId || undefined,
        azureClientId: azureClientId || undefined,
        azureClientSecret: azureClientSecret || undefined,
        gcpClientEmail: gcpClientEmail || undefined,
        gcpPrivateKey: gcpPrivateKey || undefined,
        gcpServiceAccountJson: gcpServiceAccountJson || undefined,
      });
      if (res.valid) {
        let msg = '';
        if (provider === 'AWS') {
          msg = `Conexión verificada vía AWS STS (${res.latencyMs} ms) · Identidad: ${res.arn}`;
        } else if (provider === 'AZURE') {
          msg = `Conexión verificada vía Azure ARM (${res.latencyMs} ms) · Suscripción: ${res.displayName} (${res.state})`;
        } else {
          msg = `Conexión verificada vía GCP Cloud Resource Manager (${res.latencyMs} ms) · Proyecto: ${res.projectName || res.projectId || accountOrSubscriptionId} (${res.lifecycleState || 'ACTIVE'})`;
        }
        setTestFeedback({
          valid: true,
          message: msg,
        });
      } else {
        setTestFeedback({
          valid: false,
          message: res.error ?? 'No se pudo validar la conexión con el proveedor.',
        });
      }
    } catch (err) {
      setTestFeedback({
        valid: false,
        message:
          err instanceof ApiError
            ? err.message
            : 'Error al probar la conexión con el proveedor cloud.',
      });
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const monitoredRegions = regionsText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    try {
      const created = await createMutation.mutateAsync({
        provider,
        name,
        authType,
        accountOrSubscriptionId,
        awsRoleArn: awsRoleArn || undefined,
        awsExternalId: onboardingQ.data?.awsExternalId,
        awsAccessKeyId: awsAccessKeyId || undefined,
        awsSecretAccessKey: awsSecretAccessKey || undefined,
        azureTenantId: azureTenantId || undefined,
        azureClientId: azureClientId || undefined,
        azureClientSecret: azureClientSecret || undefined,
        gcpClientEmail: gcpClientEmail || undefined,
        gcpPrivateKey: gcpPrivateKey || undefined,
        gcpServiceAccountJson: gcpServiceAccountJson || undefined,
        monitoredRegions,
        verifyOnCreate,
      });
      onCreated(created.account);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : 'No se pudo registrar la cuenta cloud.',
      );
    }
  };

  const copySnippet = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedCfn(true);
      setTimeout(() => setCopiedCfn(false), 2000);
    } catch {
      // ignore
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Conectar Cuenta Cloud (AWS / Microsoft Azure / Google Cloud)"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Selector de proveedor (Tríada Multi-Cloud) */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          <button
            type="button"
            onClick={() => switchProvider('AWS')}
            className={cn(
              'flex flex-col items-start rounded-xl border p-3 text-left transition',
              provider === 'AWS'
                ? 'border-amber-500 bg-amber-500/10 ring-2 ring-amber-500/20'
                : 'border-border hover:bg-surface-2',
            )}
          >
            <span className="text-xs font-bold text-amber-600 dark:text-amber-400">
              Amazon Web Services
            </span>
            <span className="mt-0.5 text-xs text-ink-2">
              IAM Role Cross-Account / STS
            </span>
          </button>

          <button
            type="button"
            onClick={() => switchProvider('AZURE')}
            className={cn(
              'flex flex-col items-start rounded-xl border p-3 text-left transition',
              provider === 'AZURE'
                ? 'border-sky-500 bg-sky-500/10 ring-2 ring-sky-500/20'
                : 'border-border hover:bg-surface-2',
            )}
          >
            <span className="text-xs font-bold text-sky-600 dark:text-sky-400">
              Microsoft Azure
            </span>
            <span className="mt-0.5 text-xs text-ink-2">
              Entra ID Service Principal (ARM)
            </span>
          </button>

          <button
            type="button"
            onClick={() => switchProvider('GCP')}
            className={cn(
              'flex flex-col items-start rounded-xl border p-3 text-left transition',
              provider === 'GCP'
                ? 'border-emerald-500 bg-emerald-500/10 ring-2 ring-emerald-500/20'
                : 'border-border hover:bg-surface-2',
            )}
          >
            <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400">
              Google Cloud Platform
            </span>
            <span className="mt-0.5 text-xs text-ink-2">
              Service Account Key JSON
            </span>
          </button>
        </div>

        {/* Botón rápido de Sandbox Demo */}
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-accent/25 bg-accent/5 px-3 py-2 text-xs">
          <span className="text-ink-2">
            ¿Deseas probar la evaluación CSPM sin credenciales de producción?
          </span>
          <button
            type="button"
            onClick={loadSandboxPreset}
            className="inline-flex items-center gap-1 font-semibold text-accent hover:underline"
          >
            <Sparkles className="size-3.5" /> Cargar cuenta Sandbox ({provider})
          </button>
        </div>

        {/* Plantilla de Onboarding (CloudFormation / Azure CLI / GCP Terraform) */}
        <div className="rounded-lg border border-border bg-surface-2/50 p-3 text-xs">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-ink">
              {provider === 'AWS'
                ? `External ID de tu organización: ${onboardingQ.data?.awsExternalId ?? '...'}`
                : provider === 'AZURE'
                  ? 'Comandos de provisión de solo lectura (Reader) en Azure CLI'
                  : 'Plantilla de solo lectura para GCP (Terraform / gcloud CLI)'}
            </span>
            <button
              type="button"
              onClick={() => setShowTemplate(!showTemplate)}
              className="font-medium text-accent hover:underline"
            >
              {showTemplate ? 'Ocultar plantilla' : 'Ver plantilla IaC / CLI'}
            </button>
          </div>
          {showTemplate && onboardingQ.data ? (
            <div className="mt-2 space-y-2">
              {provider === 'GCP' ? (
                <div className="flex gap-2 mb-1">
                  <button
                    type="button"
                    onClick={() => setGcpSnippetType('terraform')}
                    className={cn(
                      'px-2 py-0.5 rounded text-[10px] font-semibold transition',
                      gcpSnippetType === 'terraform'
                        ? 'bg-emerald-600 text-white'
                        : 'bg-surface border border-border text-ink-2',
                    )}
                  >
                    Terraform IaC
                  </button>
                  <button
                    type="button"
                    onClick={() => setGcpSnippetType('cli')}
                    className={cn(
                      'px-2 py-0.5 rounded text-[10px] font-semibold transition',
                      gcpSnippetType === 'cli'
                        ? 'bg-emerald-600 text-white'
                        : 'bg-surface border border-border text-ink-2',
                    )}
                  >
                    gcloud CLI Script
                  </button>
                </div>
              ) : null}
              <div className="relative rounded-lg border border-border bg-[#18181b] p-2.5 font-mono text-[11px] text-zinc-100">
                <button
                  type="button"
                  onClick={() =>
                    copySnippet(
                      provider === 'AWS'
                        ? onboardingQ.data.awsCloudFormationYaml
                        : provider === 'AZURE'
                          ? onboardingQ.data.azureCliSnippet
                          : gcpSnippetType === 'terraform'
                            ? onboardingQ.data.gcpTerraformSnippet ?? ''
                            : onboardingQ.data.gcpCliSnippet ?? '',
                    )
                  }
                  className="absolute top-2 right-2 inline-flex items-center gap-1 rounded bg-zinc-800 px-2 py-1 font-sans text-[10px] text-zinc-200 hover:bg-zinc-700"
                >
                  {copiedCfn ? (
                    <>
                      <Check className="size-3 text-emerald-400" /> Copiado
                    </>
                  ) : (
                    <>
                      <Copy className="size-3" /> Copiar
                    </>
                  )}
                </button>
                <pre className="max-h-40 overflow-auto pr-16 whitespace-pre-wrap">
                  {provider === 'AWS'
                    ? onboardingQ.data.awsCloudFormationYaml
                    : provider === 'AZURE'
                      ? onboardingQ.data.azureCliSnippet
                      : gcpSnippetType === 'terraform'
                        ? onboardingQ.data.gcpTerraformSnippet
                        : onboardingQ.data.gcpCliSnippet}
                </pre>
              </div>
            </div>
          ) : null}
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="ca-name">Nombre identificativo</Label>
            <Input
              id="ca-name"
              required
              placeholder={
                provider === 'AWS'
                  ? 'AWS Producción Principal'
                  : provider === 'AZURE'
                    ? 'Azure Suscripción Core'
                    : 'GCP Proyecto Producción'
              }
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div>
            <Label htmlFor="ca-id">
              {provider === 'AWS'
                ? 'AWS Account ID (12 dígitos)'
                : provider === 'AZURE'
                  ? 'Azure Subscription ID (UUID)'
                  : 'GCP Project ID'}
            </Label>
            <Input
              id="ca-id"
              required
              placeholder={
                provider === 'AWS'
                  ? '123456789012'
                  : provider === 'AZURE'
                    ? 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
                    : 'mi-proyecto-prod-123'
              }
              value={accountOrSubscriptionId}
              onChange={(e) => setAccountOrSubscriptionId(e.target.value)}
            />
          </div>
        </div>

        {provider === 'AWS' ? (
          <>
            <div>
              <Label htmlFor="ca-auth">Mecanismo de autenticación AWS</Label>
              <Select
                id="ca-auth"
                value={authType}
                onChange={(e) => setAuthType(e.target.value as CloudAuthType)}
              >
                <option value="ROLE_ARN">
                  Cross-Account IAM Role ARN + External ID (Recomendado)
                </option>
                <option value="ACCESS_KEYS">
                  IAM Usuario de Auditoría (Access Key ID + Secret)
                </option>
              </Select>
            </div>

            {authType === 'ROLE_ARN' ? (
              <div>
                <Label htmlFor="ca-role">IAM Role ARN</Label>
                <Input
                  id="ca-role"
                  required
                  placeholder="arn:aws:iam::123456789012:role/SSPM-Cloud-Auditor-Role"
                  value={awsRoleArn}
                  onChange={(e) => setAwsRoleArn(e.target.value)}
                />
              </div>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <Label htmlFor="ca-ak">AWS Access Key ID</Label>
                  <Input
                    id="ca-ak"
                    required
                    placeholder="AKIA..."
                    value={awsAccessKeyId}
                    onChange={(e) => setAwsAccessKeyId(e.target.value)}
                  />
                </div>
                <div>
                  <Label htmlFor="ca-sk">AWS Secret Access Key</Label>
                  <Input
                    id="ca-sk"
                    type="password"
                    required
                    placeholder="••••••••••••"
                    value={awsSecretAccessKey}
                    onChange={(e) => setAwsSecretAccessKey(e.target.value)}
                  />
                </div>
              </div>
            )}
          </>
        ) : provider === 'AZURE' ? (
          <div className="grid gap-3 sm:grid-cols-3">
            <div>
              <Label htmlFor="az-tenant">Directory (Tenant) ID</Label>
              <Input
                id="az-tenant"
                required
                placeholder="UUID de Entra ID"
                value={azureTenantId}
                onChange={(e) => setAzureTenantId(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="az-client">Application (Client) ID</Label>
              <Input
                id="az-client"
                required
                placeholder="UUID de App Registration"
                value={azureClientId}
                onChange={(e) => setAzureClientId(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="az-secret">Client Secret</Label>
              <Input
                id="az-secret"
                type="password"
                required
                placeholder="••••••••••••"
                value={azureClientSecret}
                onChange={(e) => setAzureClientSecret(e.target.value)}
              />
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <Label htmlFor="gcp-json">
                Clave Service Account JSON (Recomendado - Completa los campos automáticamente)
              </Label>
              <textarea
                id="gcp-json"
                rows={4}
                value={gcpServiceAccountJson}
                onChange={(e) => handleGcpJsonPaste(e.target.value)}
                placeholder={'{\n  "type": "service_account",\n  "project_id": "mi-proyecto",\n  "client_email": "auditor@mi-proyecto.iam.gserviceaccount.com",\n  "private_key": "-----BEGIN PRIVATE KEY-----\\n..."\n}'}
                className="w-full rounded-lg border border-border bg-surface px-3 py-2 font-mono text-xs text-ink placeholder:text-muted focus:border-accent focus:outline-none"
              />
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label htmlFor="gcp-email">Service Account Client Email</Label>
                <Input
                  id="gcp-email"
                  required
                  placeholder="sspm-auditor@proyecto.iam.gserviceaccount.com"
                  value={gcpClientEmail}
                  onChange={(e) => setGcpClientEmail(e.target.value)}
                />
              </div>

              <div>
                <Label htmlFor="gcp-pk">Private Key (PEM RSA)</Label>
                <Input
                  id="gcp-pk"
                  type="password"
                  required
                  placeholder="-----BEGIN RSA PRIVATE KEY-----..."
                  value={gcpPrivateKey}
                  onChange={(e) => setGcpPrivateKey(e.target.value)}
                />
              </div>
            </div>
          </div>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="ca-regions">Regiones a auditar (separadas por coma)</Label>
            <Input
              id="ca-regions"
              value={regionsText}
              onChange={(e) => setRegionsText(e.target.value)}
            />
          </div>

          <div className="flex items-end pb-1">
            <label className="flex items-center gap-2 text-xs text-ink-2 cursor-pointer">
              <input
                type="checkbox"
                checked={verifyOnCreate}
                onChange={(e) => setVerifyOnCreate(e.target.checked)}
                className="accent-[var(--accent)]"
              />
              Verificar conectividad STS / ARM / GCP al guardar
            </label>
          </div>
        </div>

        {testFeedback ? (
          <Alert kind={testFeedback.valid ? 'success' : 'error'}>
            {testFeedback.message}
          </Alert>
        ) : null}

        {error ? <Alert kind="error">{error}</Alert> : null}

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-3">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            loading={testMutation.isPending}
            onClick={handleTestConnection}
          >
            Probar conexión en seco
          </Button>
          <div className="flex gap-2">
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancelar
            </Button>
            <Button type="submit" loading={createMutation.isPending}>
              Guardar y Auditar
            </Button>
          </div>
        </div>
      </form>
    </Modal>
  );
}
