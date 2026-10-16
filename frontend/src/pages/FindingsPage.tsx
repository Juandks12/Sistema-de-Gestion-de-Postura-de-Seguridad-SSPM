import {
  AlertCircle,
  Calendar,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  Clock,
  Download,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  UserX,
  X,
} from 'lucide-react';
import { Fragment, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
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
import { useAssignees, useFindings, useFindingsSummary, useRetestFinding, useReviewFinding } from '@/hooks/queries';
import { ApiError, downloadFile } from '@/lib/api';
import { cn } from '@/lib/cn';
import { CATEGORY_LABEL, SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL, cvss, formatDateTime, timeAgo } from '@/lib/format';
import type { Finding, FindingCategory, FindingStatus, Severity, SlaStatus } from '@/lib/types';

type ReviewAction = 'OPEN' | 'ACCEPTED' | 'FALSE_POSITIVE';

export function FindingsPage() {
  const { user, canEdit } = useAuth();
  const [params, setParams] = useSearchParams();
  const filter = {
    assetId: params.get('assetId') ?? undefined,
    severity: (params.get('severity') ?? '') as Severity | '',
    status: (params.get('status') ?? 'OPEN') as FindingStatus | '',
    category: (params.get('category') ?? '') as FindingCategory | '',
    assignedToId: params.get('assignedToId') ?? '',
    slaStatus: (params.get('slaStatus') ?? '') as SlaStatus | '',
    page: Number(params.get('page') ?? 1),
  };
  const q = useFindings(filter);
  const summaryQ = useFindingsSummary();
  const assigneesQ = useAssignees();

  const [expanded, setExpanded] = useState<string | null>(null);
  const [review, setReview] = useState<{ finding: Finding; action: ReviewAction } | null>(null);
  const [remediationFinding, setRemediationFinding] = useState<Finding | null>(null);
  const [triageFinding, setTriageFinding] = useState<Finding | null>(null);
  const [downloading, setDownloading] = useState(false);

  const handleExport = async () => {
    setDownloading(true);
    try {
      const sp = new URLSearchParams();
      sp.set('format', 'csv');
      if (filter.assetId) sp.set('assetId', filter.assetId);
      if (filter.severity) sp.set('severity', filter.severity);
      if (filter.status) sp.set('status', filter.status);
      if (filter.category) sp.set('category', filter.category);
      if (filter.assignedToId) sp.set('assignedToId', filter.assignedToId);
      if (filter.slaStatus) sp.set('slaStatus', filter.slaStatus);
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
    setParams(next, { replace: true });
  };

  const items = q.data?.items ?? [];
  const meta = q.data?.meta;
  const slaSummary = summaryQ.data?.sla;

  const hasNonDefaultFilters = Boolean(
    filter.status !== 'OPEN' ||
    filter.severity ||
    filter.category ||
    filter.assignedToId ||
    filter.slaStatus
  );

  return (
    <>
      <PageHeader
        title="Hallazgos"
        description="Problemas detectados en tus activos con trazabilidad de ciclo de vida, asignación de responsables y control de SLAs de remediación."
        actions={
          <Button
            variant="secondary"
            icon={<Download className="size-4" />}
            onClick={handleExport}
            loading={downloading}
          >
            Exportar CSV
          </Button>
        }
      />

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

      {/* Filter Bar */}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5">
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

      <Card>
        {q.isPending ? (
          <div className="space-y-3 p-5">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : items.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="Sin hallazgos con estos filtros"
            description="Prueba a cambiar el estado, la severidad, el responsable o el filtro SLA."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th className="w-8" />
                <Th>Severidad</Th>
                <Th>Hallazgo</Th>
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
                return (
                  <Fragment key={f.id}>
                    <tr className="cursor-pointer hover:bg-surface-2/60" onClick={() => setExpanded(isOpen ? null : f.id)} aria-expanded={isOpen}>
                      <Td className="text-muted">{isOpen ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}</Td>
                      <Td>
                        <span className="sm:hidden"><SeverityBadge severity={f.severity} compact /></span>
                        <span className="hidden sm:inline"><SeverityBadge severity={f.severity} /></span>
                      </Td>
                      <Td>
                        <p className="font-medium text-ink">{f.title}</p>
                        <div className="mt-1 flex flex-wrap items-center gap-1.5 md:hidden">
                          <FindingStatusBadge status={f.status} />
                          <SlaBadge sla={f.sla} />
                        </div>
                        <p className="truncate text-xs text-muted lg:hidden mt-0.5">{f.asset.name ?? f.asset.value}</p>
                      </Td>
                      <Td className="hidden lg:table-cell">
                        <Link to={`/assets/${f.asset.id}`} className="text-ink-2 hover:underline" onClick={(e) => e.stopPropagation()}>{f.asset.name ?? f.asset.value}</Link>
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
                        <td colSpan={9} className="border-b border-line px-5 py-4">
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
        <p className="mt-3 text-xs font-semibold tracking-wide text-muted uppercase">Recomendación</p>
        <p className="mt-1 text-sm text-ink">{f.recommendation}</p>
        <dl className="mt-3 grid gap-x-6 gap-y-1 text-xs text-ink-2 sm:grid-cols-2">
          <div><dt className="inline text-muted">Ubicación: </dt><dd className="inline break-all">{f.location}</dd></div>
          <div><dt className="inline text-muted">Regla: </dt><dd className="inline">{f.ruleId} · {CATEGORY_LABEL[f.category]}</dd></div>
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
