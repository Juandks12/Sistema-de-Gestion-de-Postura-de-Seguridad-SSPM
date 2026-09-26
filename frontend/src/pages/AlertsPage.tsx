import { BellRing, CheckCheck, ChevronDown, ChevronRight, Lock, Network, ShieldAlert, type LucideIcon } from 'lucide-react';
import { Fragment, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Label, Select } from '@/components/ui/Field';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import { useAcknowledgeAlert, useAcknowledgeAllAlerts, useAlerts, useAlertsSummary } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import { ALERT_TYPE_LABEL, SEVERITY_LABEL, SEVERITY_ORDER, formatDateTime, timeAgo } from '@/lib/format';
import type { AlertItem, AlertType, DeliveryResult, Severity } from '@/lib/types';

const TYPE_ICON: Record<AlertType, LucideIcon> = {
  NEW_OPEN_PORT: Network,
  CERT_EXPIRING: Lock,
  CRITICAL_FINDING: ShieldAlert,
};

const DELIVERY_STYLE: Record<DeliveryResult['status'], { cls: string; label: string }> = {
  SENT: { cls: 'bg-good/12 text-good-text', label: 'Enviada' },
  FAILED: { cls: 'bg-critical/10 text-critical', label: 'Falló' },
  SKIPPED: { cls: 'bg-surface-2 text-ink-2', label: 'Omitida' },
};

export function AlertsPage() {
  const { canEdit, hasRole } = useAuth();
  const [params, setParams] = useSearchParams();
  const filter = {
    acknowledged: (params.get('acknowledged') ?? 'false') as 'true' | 'false' | '',
    severity: (params.get('severity') ?? '') as Severity | '',
    type: (params.get('type') ?? '') as AlertType | '',
    page: Number(params.get('page') ?? 1),
  };
  const q = useAlerts(filter);
  const summary = useAlertsSummary();
  const ackAll = useAcknowledgeAllAlerts();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    next.set(key, value);
    if (!value && key !== 'acknowledged') next.delete(key);
    next.delete('page');
    setParams(next, { replace: true });
  };

  const items = q.data?.items ?? [];
  const meta = q.data?.meta;
  const pending = summary.data?.unacknowledged ?? 0;

  const acknowledgeAll = async () => {
    setError(null);
    try {
      await ackAll.mutateAsync();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudieron marcar las alertas.');
    }
  };

  return (
    <>
      <PageHeader
        title="Alertas"
        description="Avisos tempranos generados al completar cada escaneo: puertos que se abren, certificados a punto de vencer y hallazgos críticos nuevos."
        actions={
          canEdit && pending > 0 ? (
            <Button variant="secondary" icon={<CheckCheck className="size-4" />} onClick={acknowledgeAll} loading={ackAll.isPending}>
              Marcar {pending} como revisadas
            </Button>
          ) : null
        }
      />
      {error ? <Alert kind="error" className="mb-4">{error}</Alert> : null}
      {hasRole('ADMIN') ? (
        <p className="-mt-3 mb-4 text-sm text-ink-2">
          Las alertas también se envían por correo o webhook según los <Link to="/settings" className="font-medium text-accent hover:underline">canales configurados</Link>.
        </p>
      ) : null}

      <div className="mb-4 grid gap-3 sm:grid-cols-3 lg:max-w-2xl">
        <div>
          <Label htmlFor="a-status">Estado</Label>
          <Select id="a-status" value={filter.acknowledged} onChange={(e) => setFilter('acknowledged', e.target.value)}>
            <option value="false">Pendientes</option>
            <option value="true">Revisadas</option>
            <option value="">Todas</option>
          </Select>
        </div>
        <div>
          <Label htmlFor="a-severity">Severidad</Label>
          <Select id="a-severity" value={filter.severity} onChange={(e) => setFilter('severity', e.target.value)}>
            <option value="">Todas</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="a-type">Tipo</Label>
          <Select id="a-type" value={filter.type} onChange={(e) => setFilter('type', e.target.value)}>
            <option value="">Todos</option>
            {(Object.keys(ALERT_TYPE_LABEL) as AlertType[]).map((t) => <option key={t} value={t}>{ALERT_TYPE_LABEL[t]}</option>)}
          </Select>
        </div>
      </div>

      <Card>
        {q.isPending ? (
          <div className="space-y-3 p-5">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : items.length === 0 ? (
          <EmptyState
            icon={BellRing}
            title={filter.acknowledged === 'false' ? 'No hay alertas pendientes' : 'Sin alertas con estos filtros'}
            description="Las alertas aparecen cuando un escaneo detecta un cambio relevante en tu superficie de ataque."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th className="w-8" />
                <Th>Severidad</Th>
                <Th>Alerta</Th>
                <Th className="hidden lg:table-cell">Activo</Th>
                <Th className="hidden md:table-cell">Notificación</Th>
                <Th className="hidden sm:table-cell">Fecha</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => {
                const isOpen = expanded === a.id;
                const Icon = TYPE_ICON[a.type];
                return (
                  <Fragment key={a.id}>
                    <tr className={cn('cursor-pointer hover:bg-surface-2/60', a.acknowledgedAt ? 'opacity-75' : '')} onClick={() => setExpanded(isOpen ? null : a.id)} aria-expanded={isOpen}>
                      <Td className="text-muted">{isOpen ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}</Td>
                      <Td><SeverityBadge severity={a.severity} /></Td>
                      <Td>
                        <p className="flex items-start gap-2 font-medium text-ink">
                          <Icon className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />
                          <span>{a.title}</span>
                        </p>
                        <p className="mt-0.5 pl-6 text-xs text-muted">
                          {ALERT_TYPE_LABEL[a.type]}
                          {a.acknowledgedAt ? ` · revisada${a.acknowledgedBy ? ` por ${a.acknowledgedBy.fullName}` : ''}` : ''}
                        </p>
                      </Td>
                      <Td className="hidden lg:table-cell">
                        {a.asset ? (
                          <Link to={`/assets/${a.asset.id}`} className="text-ink-2 hover:underline" onClick={(e) => e.stopPropagation()}>{a.asset.name ?? a.asset.value}</Link>
                        ) : '—'}
                      </Td>
                      <Td className="hidden md:table-cell"><DeliveriesSummary deliveries={a.deliveries} /></Td>
                      <Td className="hidden whitespace-nowrap text-ink-2 sm:table-cell" title={formatDateTime(a.createdAt)}>{timeAgo(a.createdAt)}</Td>
                    </tr>
                    {isOpen ? (
                      <tr className="bg-surface-2/40">
                        <td colSpan={6} className="border-b border-line px-5 py-4">
                          <AlertDetail alert={a} canEdit={canEdit} />
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
            <span>{meta.total} alertas · página {meta.page} de {meta.totalPages}</span>
            <div className="flex gap-2">
              <Button size="sm" variant="secondary" disabled={meta.page <= 1} onClick={() => setFilter('page', String(meta.page - 1))}>Anterior</Button>
              <Button size="sm" variant="secondary" disabled={meta.page >= meta.totalPages} onClick={() => setFilter('page', String(meta.page + 1))}>Siguiente</Button>
            </div>
          </div>
        ) : null}
      </Card>
    </>
  );
}

function DeliveriesSummary({ deliveries }: { deliveries: DeliveryResult[] | null }) {
  if (!deliveries || deliveries.length === 0) return <span className="text-xs text-muted">Solo en la plataforma</span>;
  const sent = deliveries.filter((d) => d.status === 'SENT').length;
  const failed = deliveries.filter((d) => d.status === 'FAILED').length;
  return (
    <span className="text-xs text-ink-2">
      {sent} de {deliveries.length} canal(es){failed > 0 ? <span className="ml-1 font-medium text-critical">· {failed} con error</span> : null}
    </span>
  );
}

function AlertDetail({ alert: a, canEdit }: { alert: AlertItem; canEdit: boolean }) {
  const ack = useAcknowledgeAlert();
  const [error, setError] = useState<string | null>(null);
  const acknowledge = async () => {
    setError(null);
    try {
      await ack.mutateAsync(a.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo marcar la alerta.');
    }
  };

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <p className="text-sm text-ink">{a.message}</p>
        <dl className="mt-3 grid gap-x-6 gap-y-1 text-xs text-ink-2 sm:grid-cols-2">
          <div><dt className="inline text-muted">Generada: </dt><dd className="inline">{formatDateTime(a.createdAt)}</dd></div>
          {a.acknowledgedAt ? (
            <div><dt className="inline text-muted">Revisada: </dt><dd className="inline">{formatDateTime(a.acknowledgedAt)}{a.acknowledgedBy ? ` · ${a.acknowledgedBy.fullName}` : ''}</dd></div>
          ) : null}
        </dl>
        <div className="mt-3 flex flex-wrap gap-2">
          {a.asset ? <Link to={`/assets/${a.asset.id}`} className="text-sm font-medium text-accent hover:underline">Ver activo</Link> : null}
          {a.asset ? <Link to={`/findings?assetId=${a.asset.id}&status=OPEN`} className="text-sm font-medium text-accent hover:underline">Ver hallazgos del activo</Link> : null}
        </div>
      </div>
      <div>
        <p className="text-xs font-semibold tracking-wide text-muted uppercase">Entrega por canal</p>
        {a.deliveries && a.deliveries.length > 0 ? (
          <ul className="mt-1 space-y-1.5">
            {a.deliveries.map((d) => (
              <li key={d.channelId} className="text-sm">
                <span className={cn('mr-2 inline-flex rounded-md px-1.5 py-0.5 text-xs font-medium', DELIVERY_STYLE[d.status].cls)}>{DELIVERY_STYLE[d.status].label}</span>
                <span className="text-ink">{d.channelName}</span>
                {d.error ? <p className="mt-0.5 text-xs text-muted">{d.error}</p> : null}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-1 text-sm text-ink-2">Ningún canal activo cubre esta severidad.</p>
        )}
        {canEdit && !a.acknowledgedAt ? (
          <Button size="sm" className="mt-3" icon={<CheckCheck className="size-4" />} onClick={acknowledge} loading={ack.isPending}>
            Marcar como revisada
          </Button>
        ) : null}
        {error ? <Alert kind="error" className="mt-2">{error}</Alert> : null}
      </div>
    </div>
  );
}
