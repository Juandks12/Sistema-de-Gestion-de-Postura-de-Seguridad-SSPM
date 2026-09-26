import { EyeOff, Globe, Plus, Radar, RotateCcw, ShieldCheck } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Alert } from '@/components/ui/Alert';
import { Pill } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Modal } from '@/components/ui/Modal';
import { Skeleton } from '@/components/ui/Spinner';
import { useDiscoveredHosts, useImportDiscoveredHosts, useSetDiscoveredHostIgnored } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import { formatDateTime, timeAgo } from '@/lib/format';
import type { DiscoveredHost, ImportDiscoveredResult } from '@/lib/types';

type View = 'pending' | 'inventory' | 'ignored' | 'all';

const VIEWS: Array<{ id: View; label: string }> = [
  { id: 'pending', label: 'Sin inventariar' },
  { id: 'inventory', label: 'En inventario' },
  { id: 'ignored', label: 'Descartados' },
  { id: 'all', label: 'Todos' },
];

function inView(h: DiscoveredHost, view: View): boolean {
  if (view === 'pending') return !h.ignored && !h.inventoryAssetId;
  if (view === 'inventory') return !!h.inventoryAssetId;
  if (view === 'ignored') return h.ignored && !h.inventoryAssetId;
  return true;
}

/**
 * Subdominios encontrados en Certificate Transparency (shadow IT): permite
 * incorporarlos al inventario o descartarlos.
 */
export function DiscoveredHostsCard({
  assetId,
  canEdit,
  canScan,
  onRun,
  running,
  lastRunAt,
}: {
  assetId: string;
  canEdit: boolean;
  canScan: boolean;
  onRun: () => void;
  running: boolean;
  /** Fin del último descubrimiento: al cambiar se recarga la lista. */
  lastRunAt: string | null;
}) {
  const q = useDiscoveredHosts(assetId);
  const { refetch } = q;
  useEffect(() => {
    if (lastRunAt) void refetch();
  }, [lastRunAt, refetch]);
  const setIgnored = useSetDiscoveredHostIgnored();
  const importHosts = useImportDiscoveredHosts();
  const [view, setView] = useState<View>('pending');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirming, setConfirming] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [result, setResult] = useState<ImportDiscoveredResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const items = useMemo(() => (q.data?.items ?? []).filter((h) => inView(h, view)), [q.data, view]);

  if (q.isPending) return <Skeleton className="h-48" />;
  if (!q.data) return null;
  const { summary, lastDiscovery } = q.data;
  const selectable = canEdit && view === 'pending';
  const selectedInView = items.filter((h) => selected.has(h.id));

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const doImport = async () => {
    setError(null);
    try {
      const res = await importHosts.mutateAsync(selectedInView.map((h) => h.id));
      setResult(res);
      setSelected(new Set());
      setConfirming(false);
      setAuthorized(false);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudieron registrar los subdominios.');
    }
  };

  const counts: Record<View, number> = {
    pending: summary.pending,
    inventory: summary.inInventory,
    ignored: summary.ignored,
    all: summary.total,
  };

  return (
    <Card>
      <CardHeader
        title="Subdominios descubiertos"
        subtitle={
          lastDiscovery?.finishedAt
            ? `Certificate Transparency · ${summary.total} encontrados, ${summary.resolving} resuelven en DNS · ${timeAgo(lastDiscovery.finishedAt)}`
            : 'Busca en los registros públicos de certificados TLS los subdominios que no están en el inventario.'
        }
        action={
          canEdit && canScan ? (
            <Button size="sm" variant="secondary" icon={<Radar className="size-4" />} onClick={onRun} loading={running}>
              {lastDiscovery ? 'Volver a buscar' : 'Buscar subdominios'}
            </Button>
          ) : null
        }
      />
      <CardBody className="px-0 pb-0">
        {result ? (
          <div className="px-5 pb-3">
            {result.created.length > 0 ? (
              <Alert kind="success">
                {result.created.length === 1 ? 'Se registró 1 activo' : `Se registraron ${result.created.length} activos`}
                {result.created.some((c) => !c.verified) ? '; los que no heredan la verificación del dominio deben verificarse antes de auditarlos.' : ' y ya se pueden auditar.'}
              </Alert>
            ) : null}
            {result.failed.length > 0 ? (
              <Alert kind="error" className="mt-2">
                {result.failed.map((f) => `${f.hostname}: ${f.reason}`).join(' · ')}
              </Alert>
            ) : null}
          </div>
        ) : null}

        {summary.total === 0 ? (
          <p className="px-5 pb-5 text-sm text-muted">
            {lastDiscovery ? 'No se encontraron subdominios en los certificados públicos.' : 'Todavía no se ha buscado. Se incluye en la auditoría completa del dominio.'}
          </p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-1 border-b border-line px-5 pb-3" role="tablist" aria-label="Filtrar subdominios">
              {VIEWS.map((v) => (
                <button
                  key={v.id}
                  type="button"
                  role="tab"
                  aria-selected={view === v.id}
                  onClick={() => setView(v.id)}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-sm',
                    view === v.id ? 'bg-accent/10 font-medium text-accent-strong' : 'text-ink-2 hover:bg-surface-2',
                  )}
                >
                  {v.label} <span className="tabular text-muted">{counts[v.id]}</span>
                </button>
              ))}
              {selectable && selectedInView.length > 0 ? (
                <Button size="sm" className="ml-auto" icon={<Plus className="size-4" />} onClick={() => setConfirming(true)}>
                  Añadir {selectedInView.length} al inventario
                </Button>
              ) : null}
            </div>
            {items.length === 0 ? (
              <p className="px-5 py-4 text-sm text-muted">No hay subdominios en esta vista.</p>
            ) : (
              <ul className="max-h-[26rem] divide-y divide-line overflow-y-auto">
                {items.map((h) => (
                  <li key={h.id} className="flex items-start gap-3 px-5 py-2.5">
                    {selectable ? (
                      <input
                        type="checkbox"
                        className="mt-1 size-4 shrink-0 accent-accent"
                        checked={selected.has(h.id)}
                        onChange={() => toggle(h.id)}
                        aria-label={`Seleccionar ${h.hostname}`}
                      />
                    ) : null}
                    <div className="min-w-0 flex-1">
                      <p className="flex flex-wrap items-center gap-1.5 text-sm">
                        <span className="font-medium [overflow-wrap:anywhere] text-ink">{h.hostname}</span>
                        {h.wildcard ? <Pill>Comodín</Pill> : null}
                        {h.internal ? <Pill className="border-warning/60 text-[#8a5b00] dark:text-warning">IP interna</Pill> : null}
                        {!h.resolves ? <Pill className="text-muted">No resuelve</Pill> : null}
                      </p>
                      <p className="mt-0.5 text-xs [overflow-wrap:anywhere] text-muted" title={h.lastCertificateAt ? `Último certificado: ${formatDateTime(h.lastCertificateAt)}` : undefined}>
                        {h.addresses.length > 0 ? `${h.addresses.slice(0, 3).join(', ')}${h.addresses.length > 3 ? '…' : ''} · ` : ''}
                        visto desde {timeAgo(h.firstSeenAt)}
                      </p>
                    </div>
                    {h.inventoryAssetId ? (
                      <Link to={`/assets/${h.inventoryAssetId}`} className="shrink-0 text-sm font-medium text-accent hover:underline">
                        Ver activo
                      </Link>
                    ) : canEdit ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        icon={h.ignored ? <RotateCcw className="size-4" /> : <EyeOff className="size-4" />}
                        onClick={() => setIgnored.mutate({ id: h.id, assetId, ignored: !h.ignored })}
                        disabled={setIgnored.isPending}
                      >
                        {h.ignored ? 'Restaurar' : 'Descartar'}
                      </Button>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </CardBody>

      <Modal
        open={confirming}
        onClose={() => setConfirming(false)}
        title="Añadir subdominios al inventario"
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirming(false)}>Cancelar</Button>
            <Button onClick={doImport} loading={importHosts.isPending} disabled={!authorized}>
              Añadir {selectedInView.length}
            </Button>
          </>
        }
      >
        <ul className="mb-3 max-h-40 space-y-1 overflow-y-auto text-sm text-ink">
          {selectedInView.map((h) => (
            <li key={h.id} className="flex items-center gap-2 [overflow-wrap:anywhere]">
              <Globe className="size-4 shrink-0 text-muted" aria-hidden /> {h.hostname}
            </li>
          ))}
        </ul>
        <label className="flex items-start gap-3 rounded-lg border border-border bg-surface-2/60 p-3 text-sm">
          <input type="checkbox" className="mt-0.5 size-4 accent-accent" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          <span className="text-ink-2">
            <ShieldCheck className="mr-1 inline size-4 text-accent" aria-hidden />
            Confirmo que estos subdominios son de mi organización o que está expresamente autorizada a analizarlos.
          </span>
        </label>
        {error ? <Alert kind="error" className="mt-3">{error}</Alert> : null}
      </Modal>
    </Card>
  );
}
