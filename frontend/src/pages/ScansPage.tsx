import { Radar, XCircle } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Pill, ScanStatusBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Label, Select } from '@/components/ui/Field';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import { useCancelScan, useScans } from '@/hooks/queries';
import { SCAN_STATUS_LABEL, SCAN_TYPE_LABEL, duration, formatDateTime, timeAgo } from '@/lib/format';
import type { ScanStatus, ScanType } from '@/lib/types';

export function ScansPage() {
  const { canEdit } = useAuth();
  const [params, setParams] = useSearchParams();
  const filter = {
    status: (params.get('status') ?? '') as ScanStatus | '',
    type: (params.get('type') ?? '') as ScanType | '',
    page: Number(params.get('page') ?? 1),
  };
  const q = useScans(filter);
  const cancel = useCancelScan();

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
      <PageHeader title="Escaneos" description="Historial de escaneos de la organización. Los escaneos en curso se actualizan automáticamente." />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:max-w-md">
        <div>
          <Label htmlFor="s-status">Estado</Label>
          <Select id="s-status" value={filter.status} onChange={(e) => setFilter('status', e.target.value)}>
            <option value="">Todos</option>
            {(Object.keys(SCAN_STATUS_LABEL) as ScanStatus[]).map((s) => <option key={s} value={s}>{SCAN_STATUS_LABEL[s]}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="s-type">Tipo</Label>
          <Select id="s-type" value={filter.type} onChange={(e) => setFilter('type', e.target.value)}>
            <option value="">Todos</option>
            {(Object.keys(SCAN_TYPE_LABEL) as ScanType[]).map((t) => <option key={t} value={t}>{SCAN_TYPE_LABEL[t]}</option>)}
          </Select>
        </div>
      </div>

      <Card>
        {q.isPending ? (
          <div className="space-y-3 p-5">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : items.length === 0 ? (
          <EmptyState icon={Radar} title="Sin escaneos" description="Lanza una auditoría desde la página de activos." />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Tipo</Th>
                <Th>Activo</Th>
                <Th>Estado</Th>
                <Th className="hidden md:table-cell">Resultado</Th>
                <Th className="hidden sm:table-cell">Solicitado</Th>
                <Th className="hidden lg:table-cell">Duración</Th>
                {canEdit ? <Th className="w-1" /> : null}
              </tr>
            </thead>
            <tbody>
              {items.map((s) => {
                const f = s.summary?.findings;
                const cancellable = s.status === 'PENDING' || s.status === 'RUNNING';
                return (
                  <tr key={s.id} className="hover:bg-surface-2/60">
                    <Td className="font-medium text-ink">
                      <span className="flex flex-col items-start gap-1">
                        {SCAN_TYPE_LABEL[s.type]}
                        {s.source === 'SCHEDULED' ? <Pill className="font-normal">Programado</Pill> : null}
                      </span>
                    </Td>
                    <Td>
                      <Link to={`/assets/${s.asset.id}`} className="text-ink-2 hover:underline">{s.asset.name ?? s.asset.value}</Link>
                    </Td>
                    <Td><ScanStatusBadge status={s.status} /></Td>
                    <Td className="hidden text-ink-2 md:table-cell">
                      {s.status === 'FAILED' ? (
                        <span className="text-critical" title={s.errorMessage ?? undefined}>{s.errorMessage ?? 'Error'}</span>
                      ) : s.status === 'COMPLETED' ? (
                        <span>
                          {typeof s.summary?.openPortsCount === 'number' ? `${s.summary.openPortsCount} puertos abiertos` : `${s.summary?.findingsCount ?? f?.created ?? 0} hallazgos`}
                          {f ? <span className="text-muted"> · {f.created} nuevos, {f.resolved} resueltos</span> : null}
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </Td>
                    <Td className="hidden whitespace-nowrap text-ink-2 sm:table-cell" title={formatDateTime(s.createdAt)}>{timeAgo(s.createdAt)}</Td>
                    <Td className="tabular hidden text-ink-2 lg:table-cell">{duration(s.startedAt, s.finishedAt)}</Td>
                    {canEdit ? (
                      <Td className="text-right">
                        {cancellable ? (
                          <Button size="sm" variant="ghost" icon={<XCircle className="size-4" />} onClick={() => cancel.mutate(s.id)} disabled={cancel.isPending} aria-label="Cancelar escaneo">
                            <span className="hidden sm:inline">Cancelar</span>
                          </Button>
                        ) : null}
                      </Td>
                    ) : null}
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
        {meta && meta.totalPages > 1 ? (
          <div className="flex items-center justify-between border-t border-line px-5 py-3 text-sm text-ink-2">
            <span>{meta.total} escaneos · página {meta.page} de {meta.totalPages}</span>
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
