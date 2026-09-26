import { ChevronDown, ChevronRight, ShieldAlert } from 'lucide-react';
import { Fragment, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { CveList } from '@/components/CveList';
import { Alert } from '@/components/ui/Alert';
import { FindingStatusBadge, SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Label, Select, Textarea } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import { useFindings, useReviewFinding } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { CATEGORY_LABEL, SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL, cvss, formatDateTime, timeAgo } from '@/lib/format';
import type { Finding, FindingCategory, FindingStatus, Severity } from '@/lib/types';

type ReviewAction = 'OPEN' | 'ACCEPTED' | 'FALSE_POSITIVE';

export function FindingsPage() {
  const { canEdit } = useAuth();
  const [params, setParams] = useSearchParams();
  const filter = {
    assetId: params.get('assetId') ?? undefined,
    severity: (params.get('severity') ?? '') as Severity | '',
    status: (params.get('status') ?? 'OPEN') as FindingStatus | '',
    category: (params.get('category') ?? '') as FindingCategory | '',
    page: Number(params.get('page') ?? 1),
  };
  const q = useFindings(filter);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [review, setReview] = useState<{ finding: Finding; action: ReviewAction } | null>(null);

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete('page');
    setParams(next, { replace: true });
  };

  const items = q.data?.items ?? [];
  const meta = q.data?.meta;

  return (
    <>
      <PageHeader title="Hallazgos" description="Problemas detectados en tus activos, ordenados por severidad. Acepta un riesgo o descarta un falso positivo para que deje de penalizar el score." />

      <div className="mb-4 grid gap-3 sm:grid-cols-3 lg:max-w-2xl">
        <div>
          <Label htmlFor="f-status">Estado</Label>
          <Select id="f-status" value={filter.status} onChange={(e) => setFilter('status', e.target.value)}>
            <option value="">Todos</option>
            {(Object.keys(STATUS_LABEL) as FindingStatus[]).map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-severity">Severidad</Label>
          <Select id="f-severity" value={filter.severity} onChange={(e) => setFilter('severity', e.target.value)}>
            <option value="">Todas</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-category">Categoría</Label>
          <Select id="f-category" value={filter.category} onChange={(e) => setFilter('category', e.target.value)}>
            <option value="">Todas</option>
            {(Object.keys(CATEGORY_LABEL) as FindingCategory[]).map((c) => <option key={c} value={c}>{CATEGORY_LABEL[c]}</option>)}
          </Select>
        </div>
      </div>
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
          <EmptyState icon={ShieldAlert} title="Sin hallazgos con estos filtros" description="Prueba a cambiar el estado o la severidad." />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th className="w-8" />
                <Th>Severidad</Th>
                <Th>Hallazgo</Th>
                <Th className="hidden lg:table-cell">Activo</Th>
                <Th className="hidden xl:table-cell">CVSS</Th>
                <Th className="hidden md:table-cell">Estado</Th>
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
                        <p className="truncate text-xs text-muted lg:hidden">{f.asset.name ?? f.asset.value}</p>
                      </Td>
                      <Td className="hidden lg:table-cell">
                        <Link to={`/assets/${f.asset.id}`} className="text-ink-2 hover:underline" onClick={(e) => e.stopPropagation()}>{f.asset.name ?? f.asset.value}</Link>
                      </Td>
                      <Td className="tabular hidden text-ink-2 xl:table-cell">{cvss(f.cvssScore)}</Td>
                      <Td className="hidden md:table-cell"><FindingStatusBadge status={f.status} /></Td>
                      <Td className="hidden whitespace-nowrap text-ink-2 sm:table-cell" title={formatDateTime(f.lastSeenAt)}>{timeAgo(f.lastSeenAt)}</Td>
                    </tr>
                    {isOpen ? (
                      <tr className="bg-surface-2/40">
                        <td colSpan={7} className="border-b border-line px-5 py-4">
                          <FindingDetail finding={f} canEdit={canEdit} onReview={(action) => setReview({ finding: f, action })} />
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

      {review ? <ReviewModal finding={review.finding} action={review.action} onClose={() => setReview(null)} /> : null}
    </>
  );
}

function FindingDetail({ finding: f, canEdit, onReview }: { finding: Finding; canEdit: boolean; onReview: (a: ReviewAction) => void }) {
  // Los CVE se muestran como lista; el resto de la evidencia, tal cual.
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
        </dl>
        {isCve && f.evidence ? (
          <div className="mt-4">
            <CveList evidence={f.evidence} />
          </div>
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
            {f.status !== 'ACCEPTED' ? <Button size="sm" variant="secondary" onClick={() => onReview('ACCEPTED')}>Aceptar riesgo</Button> : null}
            {f.status !== 'FALSE_POSITIVE' ? <Button size="sm" variant="secondary" onClick={() => onReview('FALSE_POSITIVE')}>Falso positivo</Button> : null}
            {f.status !== 'OPEN' ? <Button size="sm" variant="secondary" onClick={() => onReview('OPEN')}>Reabrir</Button> : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

const ACTION_LABEL: Record<ReviewAction, string> = { ACCEPTED: 'Aceptar el riesgo', FALSE_POSITIVE: 'Marcar como falso positivo', OPEN: 'Reabrir el hallazgo' };

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
