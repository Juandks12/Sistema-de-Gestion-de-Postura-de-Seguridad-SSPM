import {
  AlertCircle,
  BookOpenCheck,
  Calendar,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  Clock,
  Cloud,
  Download,
  FlaskConical,
  Layers,
  Plus,
  RefreshCw,
  Scale,
  Search,
  Server,
  ShieldAlert,
  Sparkles,
  Terminal,
  UserX,
  X,
  Zap,
} from 'lucide-react';
import { Fragment, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { AttackPathsCard } from '@/components/AttackPathsCard';
import { CveList } from '@/components/CveList';
import { FindingTriageModal } from '@/components/FindingTriageModal';
import { RemediationGuideCard } from '@/components/RemediationGuideCard';
import { Alert } from '@/components/ui/Alert';
import { FindingStatusBadge, SeverityBadge, SlaBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input, Label, Select, Textarea } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import {
  useAssignees,
  useBulkReviewFindings,
  useCreateManualFinding,
  useDashboardAssets,
  useFindings,
  useFindingsSummary,
  useGrcCatalog,
  useRetestFinding,
  useReviewFinding,
} from '@/hooks/queries';
import { ApiError, downloadFile } from '@/lib/api';
import { cn } from '@/lib/cn';
import { CATEGORY_LABEL, CLOUD_RESOURCE_TYPE_LABEL, SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL, cvss, formatDateTime, timeAgo } from '@/lib/format';
import type {
  ComplianceFramework,
  Finding,
  FindingCategory,
  FindingStatus,
  RemediationEffort,
  Severity,
  SlaStatus,
} from '@/lib/types';

type ReviewAction = 'OPEN' | 'ACCEPTED' | 'FALSE_POSITIVE';

const GRC_FRAMEWORK_PILLS: Array<{ id: ComplianceFramework; label: string; short: string }> = [
  { id: 'ISO_27001', label: 'ISO/IEC 27001:2022', short: 'ISO 27001' },
  { id: 'PCI_DSS', label: 'PCI-DSS v4.0', short: 'PCI-DSS' },
  { id: 'NIST_CSF', label: 'NIST CSF 2.0', short: 'NIST CSF' },
  { id: 'CIS_CONTROLS', label: 'CIS Controls v8', short: 'CIS v8' },
  { id: 'SOC_2', label: 'SOC 2 Type II', short: 'SOC 2' },
];

export function FindingsPage() {
  const { user, canEdit } = useAuth();
  const [params, setParams] = useSearchParams();
  const filter = {
    assetId: params.get('assetId') ?? undefined,
    cloudAccountId: params.get('cloudAccountId') ?? undefined,
    domain: (params.get('domain') ?? '') as 'perimeter' | 'cloud' | 'manual' | 'threat' | '',
    severity: (params.get('severity') ?? '') as Severity | '',
    status: (params.get('status') ?? 'OPEN') as FindingStatus | '',
    category: (params.get('category') ?? '') as FindingCategory | '',
    assignedToId: params.get('assignedToId') ?? '',
    slaStatus: (params.get('slaStatus') ?? '') as SlaStatus | '',
    effortLevel: (params.get('effortLevel') ?? '') as RemediationEffort | '',
    framework: (params.get('framework') ?? '') as ComplianceFramework | '',
    search: params.get('search') ?? '',
    page: Number(params.get('page') ?? 1),
  };
  const q = useFindings(filter);
  const summaryQ = useFindingsSummary(filter.assetId);
  const assigneesQ = useAssignees();

  const [expanded, setExpanded] = useState<string | null>(null);
  const [review, setReview] = useState<{ finding: Finding; action: ReviewAction } | null>(null);
  const [remediationFinding, setRemediationFinding] = useState<Finding | null>(null);
  const [triageFinding, setTriageFinding] = useState<Finding | null>(null);
  const [createManualOpen, setCreateManualOpen] = useState(false);
  const [bulkModalOpen, setBulkModalOpen] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [searchInput, setSearchInput] = useState(filter.search);
  const [downloading, setDownloading] = useState(false);

  const handleExport = async () => {
    setDownloading(true);
    try {
      const sp = new URLSearchParams();
      sp.set('format', 'csv');
      if (filter.assetId) sp.set('assetId', filter.assetId);
      if (filter.cloudAccountId) sp.set('cloudAccountId', filter.cloudAccountId);
      if (filter.domain) sp.set('domain', filter.domain);
      if (filter.severity) sp.set('severity', filter.severity);
      if (filter.status) sp.set('status', filter.status);
      if (filter.category) sp.set('category', filter.category);
      if (filter.assignedToId) sp.set('assignedToId', filter.assignedToId);
      if (filter.slaStatus) sp.set('slaStatus', filter.slaStatus);
      if (filter.effortLevel) sp.set('effortLevel', filter.effortLevel);
      if (filter.framework) sp.set('framework', filter.framework);
      if (filter.search) sp.set('search', filter.search);
      await downloadFile(`/findings/export?${sp.toString()}`, `findings-${new Date().toISOString().slice(0, 10)}.csv`);
    } catch (err) {
      console.error('Export error:', err);
    } finally {
      setDownloading(false);
    }
  };

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete('page');
    setParams(next, { replace: true });
  };

  const clearAllFilters = () => {
    const next = new URLSearchParams();
    if (filter.assetId) next.set('assetId', filter.assetId);
    next.set('status', 'OPEN');
    setSearchInput('');
    setParams(next, { replace: true });
  };

  const items = q.data?.items ?? [];
  const meta = q.data?.meta;
  const slaSummary = summaryQ.data?.sla;
  const bySource = summaryQ.data?.bySource;
  const byFramework = summaryQ.data?.byFramework;

  const toggleSelectOne = (id: string) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const allOnPageSelected = items.length > 0 && items.every((f) => selectedIds.includes(f.id));
  const toggleSelectPage = () => {
    if (allOnPageSelected) {
      const pageSet = new Set(items.map((f) => f.id));
      setSelectedIds((prev) => prev.filter((id) => !pageSet.has(id)));
    } else {
      const merged = new Set([...selectedIds, ...items.map((f) => f.id)]);
      setSelectedIds([...merged]);
    }
  };

  const hasNonDefaultFilters = Boolean(
    filter.status !== 'OPEN' ||
    filter.domain ||
    filter.cloudAccountId ||
    filter.severity ||
    filter.category ||
    filter.assignedToId ||
    filter.slaStatus ||
    filter.effortLevel ||
    filter.framework ||
    filter.search
  );

  return (
    <>
      <PageHeader
        title="Centro Maestro de Hallazgos y GRC"
        description="Gestión centralizada de hallazgos técnicos (Perímetro 360°, Cloud CSPM, Auditorías y Pentesting) con mapeo normativo en tiempo real (ISO 27001, PCI-DSS, NIST, CIS, SOC 2), taxonomía CWE/OWASP/MITRE y gobierno de SLAs."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {canEdit ? (
              <Button
                variant="primary"
                icon={<Plus className="size-4" />}
                onClick={() => setCreateManualOpen(true)}
              >
                Registrar Hallazgo / Auditoría
              </Button>
            ) : null}
            <Button
              variant="secondary"
              icon={<Download className="size-4" />}
              onClick={handleExport}
              loading={downloading}
            >
              Exportar CSV
            </Button>
          </div>
        }
      />

      {/* Domain selector tabs & Quick Wins Filter */}
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setFilter('domain', '')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition',
              !filter.domain
                ? 'border-accent bg-accent/10 text-accent'
                : 'border-border bg-surface text-ink-2 hover:bg-surface-2',
            )}
          >
            Todos los orígenes
            {summaryQ.data ? (
              <span className="rounded-full bg-surface-2 px-1.5 py-0.2 text-[10px] font-bold text-ink-2">
                {summaryQ.data.total}
              </span>
            ) : null}
          </button>
          <button
            type="button"
            onClick={() => setFilter('domain', filter.domain === 'perimeter' ? '' : 'perimeter')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition',
              filter.domain === 'perimeter'
                ? 'border-accent bg-accent/10 text-accent'
                : 'border-border bg-surface text-ink-2 hover:bg-surface-2',
            )}
          >
            <Server className="size-3.5" />
            Perímetro &amp; 360°
            {bySource?.PERIMETER_SCAN !== undefined ? (
              <span className="rounded-full bg-surface-2 px-1.5 py-0.2 text-[10px] font-bold text-ink-2">
                {bySource.PERIMETER_SCAN}
              </span>
            ) : null}
          </button>
          <button
            type="button"
            onClick={() => setFilter('domain', filter.domain === 'cloud' ? '' : 'cloud')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition',
              filter.domain === 'cloud'
                ? 'border-accent bg-accent/10 text-accent'
                : 'border-border bg-surface text-ink-2 hover:bg-surface-2',
            )}
          >
            <Cloud className="size-3.5" />
            Seguridad Cloud (CSPM)
            {bySource?.CLOUD_CSPM !== undefined ? (
              <span className="rounded-full bg-surface-2 px-1.5 py-0.2 text-[10px] font-bold text-ink-2">
                {bySource.CLOUD_CSPM}
              </span>
            ) : null}
          </button>
          <button
            type="button"
            onClick={() => setFilter('domain', filter.domain === 'manual' ? '' : 'manual')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition',
              filter.domain === 'manual'
                ? 'border-accent bg-accent/10 text-accent'
                : 'border-border bg-surface text-ink-2 hover:bg-surface-2',
            )}
          >
            <ClipboardCheck className="size-3.5" />
            Auditoría Manual / Pentest
            {bySource?.MANUAL_AUDIT !== undefined ? (
              <span className="rounded-full bg-surface-2 px-1.5 py-0.2 text-[10px] font-bold text-ink-2">
                {bySource.MANUAL_AUDIT}
              </span>
            ) : null}
          </button>
          <button
            type="button"
            onClick={() => setFilter('domain', filter.domain === 'threat' ? '' : 'threat')}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition',
              filter.domain === 'threat'
                ? 'border-accent bg-accent/10 text-accent'
                : 'border-border bg-surface text-ink-2 hover:bg-surface-2',
            )}
          >
            <FlaskConical className="size-3.5" />
            Laboratorio de Malware
            {bySource?.THREAT_MALWARE_LAB !== undefined ? (
              <span className="rounded-full bg-surface-2 px-1.5 py-0.2 text-[10px] font-bold text-ink-2">
                {bySource.THREAT_MALWARE_LAB}
              </span>
            ) : null}
          </button>
        </div>

        <button
          type="button"
          onClick={() => setFilter('effortLevel', filter.effortLevel === 'QUICK_WIN' ? '' : 'QUICK_WIN')}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition',
            filter.effortLevel === 'QUICK_WIN'
              ? 'border-emerald-500 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 ring-2 ring-emerald-500/20'
              : 'border-border bg-surface text-ink-2 hover:bg-surface-2',
          )}
        >
          <Zap className="size-3.5 fill-emerald-500 text-emerald-500" />
          Quick Wins 24h (&lt; 30 min)
        </button>
      </div>

      {/* GRC Normative Framework Filter Bar */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border bg-surface px-3.5 py-2.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 inline-flex items-center gap-1.5 text-xs font-semibold text-ink-2">
            <Scale className="size-3.5 text-accent" />
            Marco Normativo (GRC):
          </span>
          <button
            type="button"
            onClick={() => setFilter('framework', '')}
            className={cn(
              'rounded-md px-2.5 py-1 text-xs font-medium transition',
              !filter.framework
                ? 'bg-accent text-white shadow-xs'
                : 'bg-surface-2 text-ink-2 hover:bg-surface-2/80',
            )}
          >
            Todos
          </button>
          {GRC_FRAMEWORK_PILLS.map((fw) => {
            const active = filter.framework === fw.id;
            const count = byFramework?.[fw.id];
            return (
              <button
                key={fw.id}
                type="button"
                onClick={() => setFilter('framework', active ? '' : fw.id)}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition',
                  active
                    ? 'bg-accent text-white shadow-xs'
                    : 'bg-surface-2 text-ink-2 hover:bg-surface-2/80',
                )}
                title={`Filtrar hallazgos que impactan controles de ${fw.label}`}
              >
                <span>{fw.short}</span>
                {count !== undefined ? (
                  <span
                    className={cn(
                      'rounded-full px-1.5 text-[10px] font-bold',
                      active ? 'bg-white/20 text-white' : 'bg-surface text-muted',
                    )}
                  >
                    {count}
                  </span>
                ) : null}
              </button>
            );
          })}
        </div>

        {/* Text Search Input */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setFilter('search', searchInput.trim());
          }}
          className="flex w-full items-center gap-1.5 sm:w-72"
        >
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Buscar regla, título, URL/puerto..."
              className="w-full rounded-lg border border-border bg-surface-2/50 py-1.5 pr-7 pl-8 text-xs text-ink placeholder:text-muted focus:border-accent focus:outline-none"
            />
            {searchInput ? (
              <button
                type="button"
                onClick={() => {
                  setSearchInput('');
                  setFilter('search', '');
                }}
                className="absolute top-1/2 right-2 -translate-y-1/2 text-muted hover:text-ink"
              >
                <X className="size-3.5" />
              </button>
            ) : null}
          </div>
          <Button size="sm" variant="secondary" type="submit">
            Buscar
          </Button>
        </form>
      </div>

      {/* SLA Metrics & Quick Filter Banner */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <button
          type="button"
          onClick={() => setFilter('slaStatus', filter.slaStatus === 'OVERDUE' ? '' : 'OVERDUE')}
          className={cn(
            'group flex flex-col justify-between rounded-xl border bg-surface p-4 text-left transition shadow-xs',
            filter.slaStatus === 'OVERDUE'
              ? 'border-critical ring-2 ring-critical/20 bg-critical/5'
              : 'border-border hover:border-critical/50 hover:bg-surface-2/40'
          )}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Vencidos</span>
            <AlertCircle className="size-4 text-critical" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-critical tabular">
              {slaSummary?.overdue ?? 0}
            </span>
            <span className="text-[11px] text-muted">fuera de SLA</span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setFilter('slaStatus', filter.slaStatus === 'APPROACHING' ? '' : 'APPROACHING')}
          className={cn(
            'group flex flex-col justify-between rounded-xl border bg-surface p-4 text-left transition shadow-xs',
            filter.slaStatus === 'APPROACHING'
              ? 'border-warning ring-2 ring-warning/20 bg-warning/5'
              : 'border-border hover:border-warning/50 hover:bg-surface-2/40'
          )}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Próximos</span>
            <Clock className="size-4 text-warning" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#8a5b00] dark:text-warning tabular">
              {slaSummary?.approaching ?? 0}
            </span>
            <span className="text-[11px] text-muted">&lt; 48 horas</span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setFilter('slaStatus', filter.slaStatus === 'ON_TRACK' ? '' : 'ON_TRACK')}
          className={cn(
            'group flex flex-col justify-between rounded-xl border bg-surface p-4 text-left transition shadow-xs',
            filter.slaStatus === 'ON_TRACK'
              ? 'border-good ring-2 ring-good/20 bg-good/5'
              : 'border-border hover:border-good/50 hover:bg-surface-2/40'
          )}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">En plazo</span>
            <CheckCheck className="size-4 text-good" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-good-text tabular">
              {slaSummary?.onTrack ?? 0}
            </span>
            <span className="text-[11px] text-muted">en tiempo</span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setFilter('assignedToId', filter.assignedToId === 'unassigned' ? '' : 'unassigned')}
          className={cn(
            'group flex flex-col justify-between rounded-xl border bg-surface p-4 text-left transition shadow-xs',
            filter.assignedToId === 'unassigned'
              ? 'border-accent ring-2 ring-accent/20 bg-accent/5'
              : 'border-border hover:border-accent/50 hover:bg-surface-2/40'
          )}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Sin asignar</span>
            <UserX className="size-4 text-accent" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-ink tabular">
              {slaSummary?.unassigned ?? 0}
            </span>
            <span className="text-[11px] text-muted">sin líder</span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => setFilter('slaStatus', filter.slaStatus === 'NO_SLA' ? '' : 'NO_SLA')}
          className={cn(
            'group flex flex-col justify-between rounded-xl border bg-surface p-4 text-left transition shadow-xs col-span-2 sm:col-span-1',
            filter.slaStatus === 'NO_SLA'
              ? 'border-ink-2 ring-2 ring-ink-2/20 bg-surface-2'
              : 'border-border hover:border-border-strong hover:bg-surface-2/40'
          )}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted">Sin SLA</span>
            <Calendar className="size-4 text-muted" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-muted tabular">
              {slaSummary?.noSla ?? 0}
            </span>
            <span className="text-[11px] text-muted">sin límite</span>
          </div>
        </button>
      </div>

      {/* Attack Paths Interactive View */}
      <div className="mb-6">
        <AttackPathsCard
          assetId={filter.assetId}
          onSelectQuickWins={() => setFilter('effortLevel', 'QUICK_WIN')}
        />
      </div>

      {/* Filter Bar */}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
        <div>
          <Label htmlFor="f-status">Estado</Label>
          <Select id="f-status" value={filter.status} onChange={(e) => setFilter('status', e.target.value)}>
            <option value="">Todos los estados</option>
            {(Object.keys(STATUS_LABEL) as FindingStatus[]).map((s) => (
              <option key={s} value={s}>{STATUS_LABEL[s]}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-severity">Severidad</Label>
          <Select id="f-severity" value={filter.severity} onChange={(e) => setFilter('severity', e.target.value)}>
            <option value="">Todas las severidades</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-effort">Esfuerzo</Label>
          <Select id="f-effort" value={filter.effortLevel} onChange={(e) => setFilter('effortLevel', e.target.value)}>
            <option value="">Todos los niveles</option>
            <option value="QUICK_WIN">⚡ Quick Wins 24h</option>
            <option value="MODERATE">Moderado (&lt; 2h)</option>
            <option value="STRUCTURAL">Estructural (&gt; 4h)</option>
          </Select>
        </div>
        <div>
          <Label htmlFor="f-category">Categoría</Label>
          <Select id="f-category" value={filter.category} onChange={(e) => setFilter('category', e.target.value)}>
            <option value="">Todas las categorías</option>
            {(Object.keys(CATEGORY_LABEL) as FindingCategory[]).map((c) => (
              <option key={c} value={c}>{CATEGORY_LABEL[c]}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-assignee">Responsable</Label>
          <Select id="f-assignee" value={filter.assignedToId} onChange={(e) => setFilter('assignedToId', e.target.value)}>
            <option value="">Todos los asignados</option>
            {user ? <option value={user.id}>Mis hallazgos ({user.fullName})</option> : null}
            <option value="unassigned">Sin asignar</option>
            {(assigneesQ.data ?? []).map((u) => (
              <option key={u.id} value={u.id}>{u.fullName}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-sla">Estado SLA</Label>
          <Select id="f-sla" value={filter.slaStatus} onChange={(e) => setFilter('slaStatus', e.target.value)}>
            <option value="">Todos los SLA</option>
            <option value="OVERDUE">Vencidos</option>
            <option value="APPROACHING">Próximos a vencer (&lt;48h)</option>
            <option value="ON_TRACK">En plazo</option>
            <option value="RESOLVED">SLA Cerrado</option>
            <option value="NO_SLA">Sin fecha límite</option>
          </Select>
        </div>
      </div>

      {hasNonDefaultFilters ? (
        <div className="mb-4 flex items-center justify-between rounded-lg border border-border bg-surface px-3 py-2 text-xs text-ink-2">
          <span>Filtros activos aplicados a la lista de hallazgos.</span>
          <button
            type="button"
            onClick={clearAllFilters}
            className="font-medium text-accent hover:underline"
          >
            Restablecer filtros
          </button>
        </div>
      ) : null}

      {filter.assetId ? (
        <Alert kind="info" className="mb-4">
          Mostrando solo los hallazgos de un activo.{' '}
          <button type="button" className="font-medium underline" onClick={() => setFilter('assetId', '')}>Ver todos</button>
        </Alert>
      ) : null}

      {/* Bulk Triage Floating Bar */}
      {canEdit && selectedIds.length > 0 ? (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-accent/40 bg-accent/10 px-4 py-3 shadow-xs">
          <div className="flex items-center gap-2.5">
            <span className="inline-flex size-6 items-center justify-center rounded-full bg-accent text-xs font-bold text-white">
              {selectedIds.length}
            </span>
            <div>
              <p className="text-xs font-semibold text-ink">
                {selectedIds.length === 1
                  ? '1 hallazgo seleccionado para gobierno en lote'
                  : `${selectedIds.length} hallazgos seleccionados para gobierno en lote`}
              </p>
              <p className="text-[11px] text-ink-2">
                Asigna líder técnico, establece fecha límite SLA o actualiza el estado de remediación simultáneamente.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="primary"
              icon={<Layers className="size-3.5" />}
              onClick={() => setBulkModalOpen(true)}
            >
              Triaje y SLA en Lote
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setSelectedIds([])}
            >
              Limpiar selección
            </Button>
          </div>
        </div>
      ) : null}

      <Card>
        {q.isPending ? (
          <div className="space-y-3 p-5">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : items.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="Sin hallazgos con estos filtros"
            description="Prueba a cambiar el estado, el marco normativo GRC, la severidad o el filtro SLA."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                {canEdit ? (
                  <Th className="w-8">
                    <input
                      type="checkbox"
                      checked={allOnPageSelected}
                      onChange={toggleSelectPage}
                      aria-label="Seleccionar todos los hallazgos de la página"
                      className="size-3.5 rounded border-border accent-accent"
                    />
                  </Th>
                ) : null}
                <Th className="w-8" />
                <Th>Severidad</Th>
                <Th>Hallazgo &amp; Mapeo GRC</Th>
                <Th className="hidden lg:table-cell">Activo</Th>
                <Th className="hidden xl:table-cell">CVSS</Th>
                <Th className="hidden md:table-cell">SLA</Th>
                <Th className="hidden md:table-cell">Estado</Th>
                <Th className="hidden lg:table-cell">Responsable</Th>
                <Th className="hidden sm:table-cell">Última detección</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((f) => {
                const isOpen = expanded === f.id;
                const isSelected = selectedIds.includes(f.id);
                return (
                  <Fragment key={f.id}>
                    <tr
                      className={cn(
                        'cursor-pointer hover:bg-surface-2/60',
                        isSelected && 'bg-accent/5',
                      )}
                      onClick={() => setExpanded(isOpen ? null : f.id)}
                      aria-expanded={isOpen}
                    >
                      {canEdit ? (
                        <Td onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => toggleSelectOne(f.id)}
                            aria-label={`Seleccionar ${f.title}`}
                            className="size-3.5 rounded border-border accent-accent"
                          />
                        </Td>
                      ) : null}
                      <Td className="text-muted">{isOpen ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}</Td>
                      <Td>
                        <span className="sm:hidden"><SeverityBadge severity={f.severity} compact /></span>
                        <span className="hidden sm:inline"><SeverityBadge severity={f.severity} /></span>
                      </Td>
                      <Td>
                        <div className="flex flex-wrap items-center gap-1.5">
                          {f.sourceType === 'MANUAL_AUDIT' ? (
                            <span className="inline-flex items-center gap-1 rounded border border-violet-500/30 bg-violet-500/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-violet-600 dark:text-violet-400">
                              Auditoría / Pentest
                            </span>
                          ) : null}
                          {f.sourceType === 'THREAT_MALWARE_LAB' || f.category === 'MALWARE_THREAT' ? (
                            <Link
                              to="/threat-lab"
                              onClick={(e) => e.stopPropagation()}
                              className="inline-flex items-center gap-1 rounded border border-rose-500/30 bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-rose-600 dark:text-rose-400 hover:bg-rose-500/25"
                            >
                              <FlaskConical className="size-2.5" /> Threat Lab
                            </Link>
                          ) : null}
                          {f.cloudAccount ? (
                            <span
                              className={cn(
                                'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide',
                                f.cloudAccount.provider === 'AWS'
                                  ? 'bg-amber-500/15 text-amber-500 border border-amber-500/30'
                                  : 'bg-sky-500/15 text-sky-400 border border-sky-500/30',
                              )}
                            >
                              {f.cloudAccount.provider}
                            </span>
                          ) : null}
                          {f.cloudResource ? (
                            <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] font-medium text-ink-2">
                              {CLOUD_RESOURCE_TYPE_LABEL[f.cloudResource.resourceType] ?? f.cloudResource.resourceType}
                            </span>
                          ) : null}
                          <p className="font-medium text-ink">{f.title}</p>
                          {f.effort ? (
                            <span
                              className={cn(
                                'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold',
                                f.effort === 'QUICK_WIN'
                                  ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                                  : f.effort === 'MODERATE'
                                    ? 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20'
                                    : 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20',
                              )}
                            >
                              {f.effort === 'QUICK_WIN' && <Zap className="size-2.5 fill-emerald-500 text-emerald-500" />}
                              {f.effort === 'QUICK_WIN' ? 'Quick Win' : f.effort === 'MODERATE' ? 'Moderado' : 'Estructural'}
                              {f.estimatedMinutes ? ` (${f.estimatedMinutes}m)` : ''}
                            </span>
                          ) : null}
                          {f.complianceControls && f.complianceControls.length > 0 ? (
                            <span
                              className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[10px] font-medium text-ink-2"
                              title={f.complianceControls.map((c) => `${c.frameworkName} ${c.code}`).join(' · ')}
                            >
                              <Scale className="size-2.5 text-accent" />
                              {f.complianceControls.length} GRC
                            </span>
                          ) : null}
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-1.5 md:hidden">
                          <FindingStatusBadge status={f.status} />
                          <SlaBadge sla={f.sla} />
                        </div>
                        <p className="truncate text-xs text-muted lg:hidden mt-0.5">{f.asset.name ?? f.asset.value}</p>
                      </Td>
                      <Td className="hidden lg:table-cell">
                        {f.cloudAccount ? (
                          <div>
                            <Link to={`/cloud?accountId=${f.cloudAccount.id}&tab=resources`} className="font-medium text-ink hover:underline" onClick={(e) => e.stopPropagation()}>
                              {f.cloudAccount.name}
                            </Link>
                            {f.cloudResource ? (
                              <p className="truncate text-[11px] font-mono text-muted max-w-[180px]" title={f.cloudResource.nativeId}>
                                {f.cloudResource.name} ({f.cloudResource.region})
                              </p>
                            ) : null}
                          </div>
                        ) : (
                          <Link to={`/assets/${f.asset.id}`} className="text-ink-2 hover:underline" onClick={(e) => e.stopPropagation()}>{f.asset.name ?? f.asset.value}</Link>
                        )}
                      </Td>
                      <Td className="tabular hidden text-ink-2 xl:table-cell">{cvss(f.cvssScore)}</Td>
                      <Td className="hidden md:table-cell"><SlaBadge sla={f.sla} /></Td>
                      <Td className="hidden md:table-cell"><FindingStatusBadge status={f.status} /></Td>
                      <Td className="hidden lg:table-cell">
                        {f.assignedTo ? (
                          <span
                            className="inline-flex items-center gap-1.5 text-xs text-ink-2 truncate max-w-[140px]"
                            title={`${f.assignedTo.fullName} (${f.assignedTo.email})`}
                          >
                            <span className="size-5 shrink-0 rounded-full bg-accent/15 text-accent-strong flex items-center justify-center text-[10px] font-semibold uppercase">
                              {f.assignedTo.fullName.charAt(0)}
                            </span>
                            <span className="truncate">{f.assignedTo.fullName}</span>
                          </span>
                        ) : (
                          <span className="text-xs text-muted italic">Sin asignar</span>
                        )}
                      </Td>
                      <Td className="hidden whitespace-nowrap text-ink-2 sm:table-cell" title={formatDateTime(f.lastSeenAt)}>{timeAgo(f.lastSeenAt)}</Td>
                    </tr>
                    {isOpen ? (
                      <tr className="bg-surface-2/40">
                        <td colSpan={canEdit ? 10 : 9} className="border-b border-line px-5 py-4">
                          <FindingDetail
                            finding={f}
                            canEdit={canEdit}
                            onReview={(action) => setReview({ finding: f, action })}
                            onManageRemediation={(item) => setRemediationFinding(item)}
                            onTriage={(item) => setTriageFinding(item)}
                          />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </Table>
        )}
        {meta && meta.totalPages > 1 ? (
          <div className="flex items-center justify-between border-t border-line px-5 py-3 text-sm text-ink-2">
            <span>{meta.total} hallazgos · página {meta.page} de {meta.totalPages}</span>
            <div className="flex gap-2">
              <Button size="sm" variant="secondary" disabled={meta.page <= 1} onClick={() => setFilter('page', String(meta.page - 1))}>Anterior</Button>
              <Button size="sm" variant="secondary" disabled={meta.page >= meta.totalPages} onClick={() => setFilter('page', String(meta.page + 1))}>Siguiente</Button>
            </div>
          </div>
        ) : null}
      </Card>

      {remediationFinding ? (
        <RemediationModal
          finding={remediationFinding}
          onClose={() => setRemediationFinding(null)}
        />
      ) : null}

      {review ? <ReviewModal finding={review.finding} action={review.action} onClose={() => setReview(null)} /> : null}

      {triageFinding ? (
        <FindingTriageModal
          finding={triageFinding}
          canEdit={canEdit}
          onClose={() => setTriageFinding(null)}
        />
      ) : null}

      {createManualOpen ? (
        <CreateManualFindingModal
          defaultAssetId={filter.assetId}
          onClose={() => setCreateManualOpen(false)}
        />
      ) : null}

      {bulkModalOpen ? (
        <BulkReviewModal
          selectedIds={selectedIds}
          onSuccess={() => {
            setSelectedIds([]);
            setBulkModalOpen(false);
          }}
          onClose={() => setBulkModalOpen(false)}
        />
      ) : null}
    </>
  );
}

function FindingDetail({
  finding: f,
  canEdit,
  onReview,
  onManageRemediation,
  onTriage,
}: {
  finding: Finding;
  canEdit: boolean;
  onReview: (a: ReviewAction) => void;
  onManageRemediation: (finding: Finding) => void;
  onTriage: (finding: Finding) => void;
}) {
  const retest = useRetestFinding();
  const [retestResult, setRetestResult] = useState<{ stillReproducible: boolean; message: string } | null>(null);

  const handleRetest = async () => {
    setRetestResult(null);
    try {
      const res = await retest.mutateAsync(f.id);
      setRetestResult({
        stillReproducible: res.stillReproducible,
        message: res.message,
      });
    } catch (err) {
      setRetestResult({
        stillReproducible: true,
        message: err instanceof ApiError ? err.message : 'No se pudo completar la verificación puntual.',
      });
    }
  };

  const isCve = f.ruleId === 'VULN-KNOWN-CVE' && !!f.evidence;
  const evidence = isCve && f.evidence ? Object.fromEntries(Object.entries(f.evidence).filter(([k]) => k !== 'cves')) : f.evidence;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <p className="text-sm text-ink">{f.description}</p>
        {f.businessImpact ? (
          <div className="mt-2.5 rounded-lg border border-amber-500/20 bg-amber-500/5 p-2.5 text-xs">
            <span className="font-bold text-amber-600 dark:text-amber-400">Impacto en el negocio: </span>
            <span className="text-ink-2">{f.businessImpact}</span>
          </div>
        ) : null}

        {/* Security Taxonomy Badges (CWE, OWASP Top 10, MITRE ATT&CK) */}
        {f.cweId || f.owaspCategory || f.mitreAttackTechnique ? (
          <div className="mt-3 grid gap-2 sm:grid-cols-3">
            {f.cweId ? (
              <div className="rounded-lg border border-border bg-surface p-2.5 text-xs">
                <span className="block text-[10px] font-bold uppercase tracking-wider text-muted">Debilidad (CWE)</span>
                <span className="mt-0.5 block font-semibold text-ink">{f.cweId}</span>
              </div>
            ) : null}
            {f.owaspCategory ? (
              <div className="rounded-lg border border-border bg-surface p-2.5 text-xs">
                <span className="block text-[10px] font-bold uppercase tracking-wider text-muted">Estándar OWASP</span>
                <span className="mt-0.5 block font-semibold text-ink">{f.owaspCategory}</span>
              </div>
            ) : null}
            {f.mitreAttackTechnique ? (
              <div className="rounded-lg border border-border bg-surface p-2.5 text-xs">
                <span className="block text-[10px] font-bold uppercase tracking-wider text-muted">Técnica MITRE ATT&amp;CK</span>
                <span className="mt-0.5 block font-semibold text-ink">{f.mitreAttackTechnique}</span>
              </div>
            ) : null}
          </div>
        ) : null}

        {/* Normative & GRC Controls Mapping */}
        {f.complianceControls && f.complianceControls.length > 0 ? (
          <div className="mt-3 rounded-lg border border-border bg-surface p-3">
            <div className="flex items-center justify-between">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink">
                <BookOpenCheck className="size-3.5 text-accent" />
                Controles Normativos y de Cumplimiento Impactados ({f.complianceControls.length})
              </span>
              <Link
                to="/compliance"
                className="text-[11px] font-medium text-accent hover:underline"
              >
                Abrir Matriz GRC →
              </Link>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {f.complianceControls.map((ctrl) => (
                <Link
                  key={`${ctrl.framework}:${ctrl.code}`}
                  to={`/compliance?framework=${ctrl.framework}`}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2/60 px-2 py-1 text-[11px] text-ink-2 transition hover:border-accent/50 hover:text-ink"
                  title={`${ctrl.frameworkName} — ${ctrl.code}: ${ctrl.title} (${ctrl.domain})`}
                >
                  <span className="font-bold text-accent">{ctrl.frameworkName}</span>
                  <span className="font-mono font-semibold text-ink">{ctrl.code}</span>
                  <span className="hidden sm:inline text-muted">· {ctrl.title}</span>
                </Link>
              ))}
            </div>
          </div>
        ) : null}

        <p className="mt-3 text-xs font-semibold tracking-wide text-muted uppercase">Recomendación</p>
        <p className="mt-1 text-sm text-ink">{f.recommendation}</p>
        <dl className="mt-3 grid gap-x-6 gap-y-1 text-xs text-ink-2 sm:grid-cols-2">
          <div><dt className="inline text-muted">Ubicación: </dt><dd className="inline break-all">{f.location}</dd></div>
          <div><dt className="inline text-muted">Regla: </dt><dd className="inline">{f.ruleId} · {CATEGORY_LABEL[f.category]}</dd></div>
          {f.effort ? (
            <div>
              <dt className="inline text-muted">Esfuerzo estimado: </dt>
              <dd className="inline font-semibold">
                {f.effort === 'QUICK_WIN' ? 'Quick Win (< 30 min)' : f.effort === 'MODERATE' ? 'Moderado (< 2 horas)' : 'Estructural (> 4 horas)'}
                {f.estimatedMinutes ? ` · ${f.estimatedMinutes} min` : ''}
              </dd>
            </div>
          ) : null}
          <div><dt className="inline text-muted">Primera detección: </dt><dd className="inline">{formatDateTime(f.firstSeenAt)}</dd></div>
          <div><dt className="inline text-muted">Última detección: </dt><dd className="inline">{formatDateTime(f.lastSeenAt)}</dd></div>
          <div>
            <dt className="inline text-muted">Asignado a: </dt>
            <dd className="inline font-medium text-ink">
              {f.assignedTo ? `${f.assignedTo.fullName} (${f.assignedTo.email})` : <span className="text-muted italic">Sin asignar</span>}
            </dd>
          </div>
          <div>
            <dt className="inline text-muted">Fecha límite (SLA): </dt>
            <dd className="inline font-medium text-ink">
              {f.dueDate ? (
                <span className="inline-flex items-center gap-1.5">
                  {formatDateTime(f.dueDate)}
                  <SlaBadge sla={f.sla} />
                </span>
              ) : (
                <span className="text-muted italic">Sin fecha configurada</span>
              )}
            </dd>
          </div>
        </dl>
        {isCve && f.evidence ? (
          <div className="mt-4">
            <CveList evidence={f.evidence} />
          </div>
        ) : null}
        {f.remediationCli || f.remediationIac ? (
          <div className="mt-3 space-y-2 rounded-lg border border-border bg-surface p-3">
            <p className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink">
              <Terminal className="size-3.5 text-accent" />
              Automatización de Remediación Directa (CLI / IaC)
            </p>
            {f.remediationCli ? (
              <div>
                <span className="text-[11px] font-medium text-muted">Comando CLI sugerido:</span>
                <pre className="mt-1 overflow-x-auto rounded bg-surface-2 p-2 font-mono text-xs text-ink">{f.remediationCli}</pre>
              </div>
            ) : null}
            {f.remediationIac ? (
              <div>
                <span className="text-[11px] font-medium text-muted">Infraestructura como Código (Terraform / IaC):</span>
                <pre className="mt-1 overflow-x-auto rounded bg-surface-2 p-2 font-mono text-xs text-ink">{f.remediationIac}</pre>
              </div>
            ) : null}
          </div>
        ) : null}
        {f.remediationGuide ? (
          <RemediationGuideCard guide={f.remediationGuide} />
        ) : null}
        {f.remediationNote ? (
          <p className="mt-3 rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-sm text-ink-2">
            <span className="font-medium text-amber-500">Nota técnica de remediación: </span>{f.remediationNote}
          </p>
        ) : null}
        {f.reviewNote ? (
          <p className="mt-3 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink-2">
            <span className="font-medium text-ink">Nota de revisión{f.reviewedBy ? ` (${f.reviewedBy.fullName})` : ''}: </span>{f.reviewNote}
          </p>
        ) : null}
      </div>
      <div>
        {evidence && Object.keys(evidence).length > 0 ? (
          <>
            <p className="text-xs font-semibold tracking-wide text-muted uppercase">Evidencia</p>
            <pre className="mt-1 max-h-48 overflow-auto rounded-lg border border-border bg-surface p-3 text-xs text-ink-2">{JSON.stringify(evidence, null, 2)}</pre>
          </>
        ) : null}
        {canEdit ? (
          <div className="mt-3 flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="primary"
              icon={<Clock className="size-3.5" />}
              onClick={() => onManageRemediation(f)}
              title="Gestionar estado, responsable asignado y SLA de remediación"
            >
              Gestionar SLA y Remediación
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<Sparkles className="size-3.5 text-accent-strong" />}
              onClick={() => onTriage(f)}
              title="Analizar con motor heurístico y síntesis de IA para triage contextual y detección de falsos positivos"
            >
              Triage IA
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={<RefreshCw className="size-3.5" />}
              loading={retest.isPending}
              onClick={handleRetest}
              title="Disparar sonda rápida (2-5s) sobre la ubicación para verificar si ya fue remediado"
            >
              Re-verificar
            </Button>
            {f.status !== 'ACCEPTED' ? <Button size="sm" variant="secondary" onClick={() => onReview('ACCEPTED')}>Aceptar riesgo</Button> : null}
            {f.status !== 'FALSE_POSITIVE' ? <Button size="sm" variant="secondary" onClick={() => onReview('FALSE_POSITIVE')}>Falso positivo</Button> : null}
            {f.status !== 'OPEN' ? <Button size="sm" variant="secondary" onClick={() => onReview('OPEN')}>Reabrir</Button> : null}
          </div>
        ) : null}
        {retestResult ? (
          <div className="mt-3">
            <Alert kind={retestResult.stillReproducible ? 'error' : 'success'}>
              {retestResult.message}
            </Alert>
          </div>
        ) : null}
      </div>
    </div>
  );
}

const REVIEWABLE_STATUS_LIST: FindingStatus[] = [
  'OPEN',
  'IN_PROGRESS',
  'VERIFYING',
  'ACCEPTED',
  'FALSE_POSITIVE',
];

interface RemediationModalProps {
  finding: Finding;
  onClose: () => void;
}

function RemediationModal({ finding, onClose }: RemediationModalProps) {
  const review = useReviewFinding();
  const assigneesQ = useAssignees();

  const [status, setStatus] = useState<FindingStatus>(finding.status);
  const [assignedToId, setAssignedToId] = useState<string>(finding.assignedToId ?? '');
  const [dueDate, setDueDate] = useState<string>(
    finding.dueDate ? new Date(finding.dueDate).toISOString().slice(0, 10) : ''
  );
  const [remediationNote, setRemediationNote] = useState<string>(finding.remediationNote ?? '');
  const [note, setNote] = useState<string>(finding.reviewNote ?? '');
  const [error, setError] = useState<string | null>(null);

  const setPresetDays = (days: number) => {
    const target = new Date();
    target.setDate(target.getDate() + days);
    setDueDate(target.toISOString().slice(0, 10));
  };

  const handleSubmit = async () => {
    setError(null);
    try {
      const payload: {
        id: string;
        status: FindingStatus;
        assignedToId: string | null;
        dueDate: string | null;
        remediationNote: string | null;
        note?: string;
      } = {
        id: finding.id,
        status,
        assignedToId: assignedToId ? assignedToId : null,
        dueDate: dueDate ? new Date(`${dueDate}T23:59:59.999Z`).toISOString() : null,
        remediationNote: remediationNote.trim() ? remediationNote.trim() : null,
      };

      if (note.trim()) {
        payload.note = note.trim();
      }

      await review.mutateAsync(payload);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo guardar la gestión de remediación.');
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Gestión de Ciclo de Vida y SLA de Remediación"
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={review.isPending}>
            Cancelar
          </Button>
          <Button onClick={handleSubmit} loading={review.isPending}>
            Guardar cambios
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {/* Finding header chip banner */}
        <div className="rounded-lg border border-border bg-surface-2/40 p-3.5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <FindingStatusBadge status={finding.status} />
            <SlaBadge sla={finding.sla} />
          </div>
          <p className="mt-2 text-sm font-semibold text-ink">{finding.title}</p>
          <p className="text-xs text-muted break-all">{finding.asset.name ?? finding.asset.value} · {finding.location}</p>
        </div>

        {/* Status and Assignee Grid */}
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="rem-status">Estado del hallazgo</Label>
            <Select
              id="rem-status"
              value={status}
              onChange={(e) => setStatus(e.target.value as FindingStatus)}
            >
              {finding.status === 'RESOLVED' ? (
                <option value="RESOLVED" disabled>Resuelto (Automático por escáner)</option>
              ) : null}
              {REVIEWABLE_STATUS_LIST.map((s) => (
                <option key={s} value={s}>{STATUS_LABEL[s]}</option>
              ))}
            </Select>
            <p className="mt-1 text-[11px] text-muted">
              {status === 'ACCEPTED' || status === 'FALSE_POSITIVE'
                ? 'Este estado exime el hallazgo del cálculo de riesgo y Security Score.'
                : 'Controla el flujo de atención técnica del equipo.'}
            </p>
          </div>

          <div>
            <Label htmlFor="rem-assignee">Responsable asignado</Label>
            <Select
              id="rem-assignee"
              value={assignedToId}
              onChange={(e) => setAssignedToId(e.target.value)}
            >
              <option value="">(Sin asignar)</option>
              {(assigneesQ.data ?? []).map((u) => (
                <option key={u.id} value={u.id}>
                  {u.fullName} ({u.email})
                </option>
              ))}
            </Select>
            <p className="mt-1 text-[11px] text-muted">
              Miembro de la organización responsable de liderar la remediación.
            </p>
          </div>
        </div>

        {/* SLA Due Date section */}
        <div className="rounded-lg border border-border bg-surface p-3.5">
          <div className="flex items-center justify-between">
            <Label htmlFor="rem-due-date" hint="(Fecha límite SLA)">
              Plazo de Remediación
            </Label>
            {dueDate ? (
              <span className="text-xs text-ink-2">
                Seleccionado: <strong className="text-ink">{dueDate}</strong>
              </span>
            ) : null}
          </div>
          <Input
            id="rem-due-date"
            type="date"
            value={dueDate}
            onChange={(e) => setDueDate(e.target.value)}
            className="mt-1"
          />

          {/* Quick preset buttons */}
          <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-muted mr-1">Presets SLA:</span>
            <button
              type="button"
              onClick={() => setPresetDays(7)}
              className="rounded-md border border-critical/30 bg-critical/10 px-2 py-0.5 text-xs font-medium text-critical hover:bg-critical/20"
              title="7 días (recomendado para Crítico)"
            >
              +7d (Crítico)
            </button>
            <button
              type="button"
              onClick={() => setPresetDays(15)}
              className="rounded-md border border-warning/30 bg-warning/10 px-2 py-0.5 text-xs font-medium text-[#8a5b00] dark:text-warning hover:bg-warning/20"
              title="15 días (recomendado para Alto)"
            >
              +15d (Alto)
            </button>
            <button
              type="button"
              onClick={() => setPresetDays(30)}
              className="rounded-md border border-line bg-surface-2 px-2 py-0.5 text-xs font-medium text-ink-2 hover:bg-surface-2/80"
              title="30 días (recomendado para Medio)"
            >
              +30d (Medio)
            </button>
            <button
              type="button"
              onClick={() => setPresetDays(60)}
              className="rounded-md border border-line bg-surface-2 px-2 py-0.5 text-xs font-medium text-ink-2 hover:bg-surface-2/80"
              title="60 días (recomendado para Bajo)"
            >
              +60d (Bajo)
            </button>
            {dueDate ? (
              <button
                type="button"
                onClick={() => setDueDate('')}
                className="ml-auto inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium text-muted hover:text-ink"
              >
                <X className="size-3" />
                Quitar fecha
              </button>
            ) : null}
          </div>
        </div>

        {/* Technical Remediation Note */}
        <div>
          <Label htmlFor="rem-technical-note" hint="(opcional)">
            Nota Técnica de Remediación
          </Label>
          <Textarea
            id="rem-technical-note"
            rows={2}
            value={remediationNote}
            onChange={(e) => setRemediationNote(e.target.value)}
            placeholder="Ej.: Se aplicó la actualización OpenSSL 3.0.12 y se cerró el puerto no utilizado en firewall."
          />
        </div>

        {/* Review / Justification Note */}
        <div>
          <Label htmlFor="rem-review-note" hint="(opcional)">
            Justificación / Comentario de Revisión
          </Label>
          <Textarea
            id="rem-review-note"
            rows={2}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Ej.: Compensación técnica aprobada por el CISO; excepción temporal válida hasta fin de mes."
          />
        </div>

        {error ? <Alert kind="error">{error}</Alert> : null}
      </div>
    </Modal>
  );
}

const ACTION_LABEL: Record<ReviewAction, string> = {
  ACCEPTED: 'Aceptar el riesgo',
  FALSE_POSITIVE: 'Marcar como falso positivo',
  OPEN: 'Reabrir el hallazgo',
};

function ReviewModal({ finding, action, onClose }: { finding: Finding; action: ReviewAction; onClose: () => void }) {
  const review = useReviewFinding();
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    try {
      await review.mutateAsync({ id: finding.id, status: action, note: note.trim() || undefined });
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo guardar la revisión.');
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={ACTION_LABEL[action]}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancelar</Button>
          <Button onClick={submit} loading={review.isPending}>Confirmar</Button>
        </>
      }
    >
      <p className="text-sm text-ink-2">
        <span className="font-medium text-ink">{finding.title}</span> · {finding.asset.name ?? finding.asset.value}
      </p>
      {action !== 'OPEN' ? <p className="mt-2 text-sm text-ink-2">El hallazgo dejará de penalizar el Security Score y conservará este estado aunque vuelva a detectarse.</p> : null}
      <div className="mt-4">
        <Label htmlFor="review-note" hint="(opcional)">Justificación</Label>
        <Textarea id="review-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Ej.: puerto necesario para el proveedor de pagos; acceso restringido por firewall." />
      </div>
      {error ? <Alert kind="error" className="mt-3">{error}</Alert> : null}
    </Modal>
  );
}

function BulkReviewModal({
  selectedIds,
  onSuccess,
  onClose,
}: {
  selectedIds: string[];
  onSuccess: () => void;
  onClose: () => void;
}) {
  const bulkReview = useBulkReviewFindings();
  const assigneesQ = useAssignees();

  const [status, setStatus] = useState<FindingStatus | ''>('');
  const [assignedToId, setAssignedToId] = useState<string>('__UNCHANGED__');
  const [dueDate, setDueDate] = useState<string>('');
  const [remediationNote, setRemediationNote] = useState<string>('');
  const [note, setNote] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    setError(null);
    try {
      await bulkReview.mutateAsync({
        findingIds: selectedIds,
        ...(status ? { status } : {}),
        ...(assignedToId !== '__UNCHANGED__'
          ? { assignedToId: assignedToId ? assignedToId : null }
          : {}),
        ...(dueDate ? { dueDate: new Date(`${dueDate}T23:59:59.999Z`).toISOString() } : {}),
        ...(remediationNote.trim() ? { remediationNote: remediationNote.trim() } : {}),
        ...(note.trim() ? { note: note.trim() } : {}),
      });
      onSuccess();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo aplicar el triaje en lote.');
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={`Gobierno y Triaje en Lote (${selectedIds.length} hallazgos)`}
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={bulkReview.isPending}>
            Cancelar
          </Button>
          <Button onClick={handleSubmit} loading={bulkReview.isPending}>
            Aplicar a {selectedIds.length} hallazgos
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-xs text-ink-2">
          Solo los campos que modifiques se aplicarán al lote seleccionado. Si cambias el estado de remediación, se recalculará el Security Score de todos los activos afectados.
        </p>

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="bulk-status">Cambiar estado a</Label>
            <Select
              id="bulk-status"
              value={status}
              onChange={(e) => setStatus(e.target.value as FindingStatus | '')}
            >
              <option value="">(Conservar estado actual)</option>
              {REVIEWABLE_STATUS_LIST.map((s) => (
                <option key={s} value={s}>{STATUS_LABEL[s]}</option>
              ))}
            </Select>
          </div>

          <div>
            <Label htmlFor="bulk-assignee">Asignar responsable</Label>
            <Select
              id="bulk-assignee"
              value={assignedToId}
              onChange={(e) => setAssignedToId(e.target.value)}
            >
              <option value="__UNCHANGED__">(Conservar responsable actual)</option>
              <option value="">(Dejar sin asignar)</option>
              {(assigneesQ.data ?? []).map((u) => (
                <option key={u.id} value={u.id}>
                  {u.fullName} ({u.email})
                </option>
              ))}
            </Select>
          </div>
        </div>

        <div>
          <Label htmlFor="bulk-due-date" hint="(opcional)">
            Establecer Fecha Límite SLA común
          </Label>
          <Input
            id="bulk-due-date"
            type="date"
            value={dueDate}
            onChange={(e) => setDueDate(e.target.value)}
          />
        </div>

        <div>
          <Label htmlFor="bulk-rem-note" hint="(opcional)">
            Nota técnica de remediación para el lote
          </Label>
          <Textarea
            id="bulk-rem-note"
            rows={2}
            value={remediationNote}
            onChange={(e) => setRemediationNote(e.target.value)}
            placeholder="Ej.: Incluido en el Sprint DevSecOps Q4 — Ticket JIRA SEC-412."
          />
        </div>

        <div>
          <Label htmlFor="bulk-review-note" hint="(opcional)">
            Justificación / Nota de auditoría
          </Label>
          <Textarea
            id="bulk-review-note"
            rows={2}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Ej.: Aprobado en comité de seguridad."
          />
        </div>

        {error ? <Alert kind="error">{error}</Alert> : null}
      </div>
    </Modal>
  );
}

function CreateManualFindingModal({
  defaultAssetId,
  onClose,
}: {
  defaultAssetId?: string;
  onClose: () => void;
}) {
  const createManual = useCreateManualFinding();
  const assetsQ = useDashboardAssets();
  const assigneesQ = useAssignees();
  const grcQ = useGrcCatalog();

  const assets = assetsQ.data?.items ?? [];
  const [assetId, setAssetId] = useState<string>(defaultAssetId ?? '');
  const [severity, setSeverity] = useState<Severity>('HIGH');
  const [category, setCategory] = useState<FindingCategory>('VULNERABLE_SOFTWARE');
  const [title, setTitle] = useState('');
  const [location, setLocation] = useState('');
  const [description, setDescription] = useState('');
  const [recommendation, setRecommendation] = useState('');
  const [cweId, setCweId] = useState('');
  const [owaspCategory, setOwaspCategory] = useState('');
  const [mitreAttackTechnique, setMitreAttackTechnique] = useState('');
  const [effort, setEffort] = useState<RemediationEffort>('MODERATE');
  const [businessImpact, setBusinessImpact] = useState('');
  const [remediationCli, setRemediationCli] = useState('');
  const [assignedToId, setAssignedToId] = useState('');
  const [dueDate, setDueDate] = useState('');
  const [selectedControlIds, setSelectedControlIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const effectiveAssetId = assetId || (assets[0]?.id ?? '');

  const toggleControl = (ctrlKey: string) => {
    setSelectedControlIds((prev) =>
      prev.includes(ctrlKey) ? prev.filter((x) => x !== ctrlKey) : [...prev, ctrlKey],
    );
  };

  const handleSubmit = async () => {
    setError(null);
    if (!effectiveAssetId) {
      setError('Selecciona el activo afectado.');
      return;
    }
    if (title.trim().length < 5 || description.trim().length < 10 || recommendation.trim().length < 5 || !location.trim()) {
      setError('Completa el título, la ubicación/endpoint, la descripción técnica y la recomendación.');
      return;
    }

    try {
      await createManual.mutateAsync({
        assetId: effectiveAssetId,
        severity,
        category,
        title: title.trim(),
        location: location.trim(),
        description: description.trim(),
        recommendation: recommendation.trim(),
        effort,
        ...(cweId.trim() ? { cweId: cweId.trim() } : {}),
        ...(owaspCategory.trim() ? { owaspCategory: owaspCategory.trim() } : {}),
        ...(mitreAttackTechnique.trim() ? { mitreAttackTechnique: mitreAttackTechnique.trim() } : {}),
        ...(businessImpact.trim() ? { businessImpact: businessImpact.trim() } : {}),
        ...(remediationCli.trim() ? { remediationCli: remediationCli.trim() } : {}),
        ...(assignedToId ? { assignedToId } : {}),
        ...(dueDate ? { dueDate: new Date(`${dueDate}T23:59:59.999Z`).toISOString() } : {}),
        ...(selectedControlIds.length > 0 ? { complianceControlIds: selectedControlIds } : {}),
      });
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo registrar el hallazgo manual.');
    }
  };

  const controls = grcQ.data?.controls ?? [];

  return (
    <Modal
      open
      onClose={onClose}
      title="Registrar Hallazgo de Seguridad / Auditoría Manual / Pentest"
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={createManual.isPending}>
            Cancelar
          </Button>
          <Button onClick={handleSubmit} loading={createManual.isPending}>
            Registrar hallazgo en el Centro Maestro
          </Button>
        </>
      }
    >
      <div className="max-h-[72vh] space-y-4 overflow-y-auto pr-1">
        <p className="text-xs text-ink-2">
          Registra hallazgos provenientes de pruebas de penetración (Pentesting), auditorías internas/externas (ISO 27001, PCI-DSS, SOC 2) o revisiones de arquitectura para consolidar su ciclo de vida, SLA y cumplimiento normativo en un solo repositorio.
        </p>

        <div className="grid gap-3 sm:grid-cols-3">
          <div>
            <Label htmlFor="man-asset">Activo afectado</Label>
            <Select
              id="man-asset"
              value={effectiveAssetId}
              onChange={(e) => setAssetId(e.target.value)}
            >
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name ? `${a.name} (${a.value})` : a.value}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="man-severity">Severidad</Label>
            <Select
              id="man-severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity)}
            >
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="man-category">Categoría técnica</Label>
            <Select
              id="man-category"
              value={category}
              onChange={(e) => setCategory(e.target.value as FindingCategory)}
            >
              {(Object.keys(CATEGORY_LABEL) as FindingCategory[]).map((c) => (
                <option key={c} value={c}>{CATEGORY_LABEL[c]}</option>
              ))}
            </Select>
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="man-title">Título del hallazgo</Label>
            <Input
              id="man-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Ej.: IDOR en endpoint de descarga de extractos"
            />
          </div>
          <div>
            <Label htmlFor="man-location">Ubicación / Endpoint / Recurso</Label>
            <Input
              id="man-location"
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              placeholder="Ej.: https://api.midominio.com/v1/statements/{id}"
            />
          </div>
        </div>

        <div>
          <Label htmlFor="man-desc">Descripción técnica y evidencia de auditoría</Label>
          <Textarea
            id="man-desc"
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describe el vector identificado, los pasos de reproducción y el alcance observado..."
          />
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="man-rec">Recomendación de remediación</Label>
            <Textarea
              id="man-rec"
              rows={2}
              value={recommendation}
              onChange={(e) => setRecommendation(e.target.value)}
              placeholder="Ej.: Validar pertenencia del recurso contra el tenantId del JWT autenticado..."
            />
          </div>
          <div>
            <Label htmlFor="man-impact" hint="(opcional)">Impacto en el negocio</Label>
            <Textarea
              id="man-impact"
              rows={2}
              value={businessImpact}
              onChange={(e) => setBusinessImpact(e.target.value)}
              placeholder="Ej.: Exposición de información financiera confidencial de otros clientes..."
            />
          </div>
        </div>

        {/* Taxonomía CWE / OWASP / MITRE */}
        <div className="grid gap-3 sm:grid-cols-3">
          <div>
            <Label htmlFor="man-cwe" hint="(opcional)">CWE ID</Label>
            <Input
              id="man-cwe"
              value={cweId}
              onChange={(e) => setCweId(e.target.value)}
              placeholder="Ej.: CWE-639: IDOR"
            />
          </div>
          <div>
            <Label htmlFor="man-owasp" hint="(opcional)">Categoría OWASP</Label>
            <Input
              id="man-owasp"
              value={owaspCategory}
              onChange={(e) => setOwaspCategory(e.target.value)}
              placeholder="Ej.: A01:2021 - Broken Access Control"
            />
          </div>
          <div>
            <Label htmlFor="man-mitre" hint="(opcional)">Técnica MITRE ATT&amp;CK</Label>
            <Input
              id="man-mitre"
              value={mitreAttackTechnique}
              onChange={(e) => setMitreAttackTechnique(e.target.value)}
              placeholder="Ej.: T1190 - Exploit Public App"
            />
          </div>
        </div>

        {/* Controles GRC Impactados */}
        {controls.length > 0 ? (
          <div className="rounded-lg border border-border bg-surface-2/40 p-3">
            <Label hint={`(${selectedControlIds.length} seleccionados)`}>
              Controles Normativos y Estándares Impactados (ISO 27001, PCI-DSS, NIST, CIS, SOC 2)
            </Label>
            <div className="mt-2 flex max-h-32 flex-wrap gap-1.5 overflow-y-auto">
              {controls.map((c) => {
                const key = `${c.framework}:${c.code}`;
                const active = selectedControlIds.includes(key);
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => toggleControl(key)}
                    className={cn(
                      'rounded-md border px-2 py-1 text-[11px] font-medium transition text-left',
                      active
                        ? 'border-accent bg-accent text-white'
                        : 'border-border bg-surface text-ink-2 hover:bg-surface-2',
                    )}
                    title={`${c.frameworkName} ${c.code} — ${c.title}`}
                  >
                    <span className="font-bold">{c.frameworkName}</span> {c.code}
                  </button>
                );
              })}
            </div>
          </div>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-3">
          <div>
            <Label htmlFor="man-effort">Esfuerzo estimado</Label>
            <Select
              id="man-effort"
              value={effort}
              onChange={(e) => setEffort(e.target.value as RemediationEffort)}
            >
              <option value="QUICK_WIN">Quick Win (&lt; 30 min)</option>
              <option value="MODERATE">Moderado (&lt; 2 horas)</option>
              <option value="STRUCTURAL">Estructural (&gt; 4 horas)</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="man-assignee" hint="(opcional)">Asignar responsable</Label>
            <Select
              id="man-assignee"
              value={assignedToId}
              onChange={(e) => setAssignedToId(e.target.value)}
            >
              <option value="">(Sin asignar)</option>
              {(assigneesQ.data ?? []).map((u) => (
                <option key={u.id} value={u.id}>{u.fullName}</option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="man-due" hint="(opcional)">Fecha límite SLA</Label>
            <Input
              id="man-due"
              type="date"
              value={dueDate}
              onChange={(e) => setDueDate(e.target.value)}
            />
          </div>
        </div>

        <div>
          <Label htmlFor="man-cli" hint="(opcional)">Comando CLI o Snippet de Remediación</Label>
          <Input
            id="man-cli"
            value={remediationCli}
            onChange={(e) => setRemediationCli(e.target.value)}
            placeholder="Ej.: aws s3api put-public-access-block --bucket mi-bucket ..."
          />
        </div>

        {error ? <Alert kind="error">{error}</Alert> : null}
      </div>
    </Modal>
  );
}
