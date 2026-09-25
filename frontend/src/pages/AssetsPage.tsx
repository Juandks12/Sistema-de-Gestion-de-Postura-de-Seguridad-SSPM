import { Plus, Radar, Server, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { GradeBadge } from '@/components/ui/Badge';
import { SEVERITY_STYLE } from '@/components/ui/styles';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input, Label } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import { useCreateAsset, useDashboardAssets, useRequestScan } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import { SEVERITY_LABEL, timeAgo } from '@/lib/format';
import type { DashboardAsset } from '@/lib/types';

export function AssetsPage() {
  const { canEdit } = useAuth();
  const assets = useDashboardAssets();
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const requestScan = useRequestScan();

  const audit = async (a: DashboardAsset) => {
    setNotice(null);
    try {
      const res = await requestScan.mutateAsync({ assetId: a.id });
      setNotice({ kind: 'success', text: `Auditoría de ${a.name ?? a.value}: ${res.queued.length} escaneos encolados${res.skipped.length ? `, ${res.skipped.length} omitidos por estar en curso` : ''}.` });
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof ApiError ? err.message : 'No se pudo encolar la auditoría.' });
    }
  };

  return (
    <>
      <PageHeader
        title="Activos"
        description="Dominios e IPs públicas de tu organización, ordenados por peor postura."
        actions={canEdit ? <Button icon={<Plus className="size-4" />} onClick={() => setOpen(true)}>Registrar activo</Button> : null}
      />
      {notice ? <Alert kind={notice.kind} className="mb-4">{notice.text}</Alert> : null}

      <Card>
        {assets.isPending ? (
          <div className="space-y-3 p-5">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : !assets.data || assets.data.items.length === 0 ? (
          <EmptyState icon={Server} title="Aún no hay activos" description="Registra el dominio o la IP pública de un servicio que tu organización esté autorizada a analizar." action={canEdit ? <Button onClick={() => setOpen(true)}>Registrar el primero</Button> : undefined} />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Activo</Th>
                <Th className="w-24">Score</Th>
                <Th className="hidden md:table-cell">Hallazgos abiertos</Th>
                <Th className="hidden sm:table-cell">Último escaneo</Th>
                <Th className="w-1 text-right">Acciones</Th>
              </tr>
            </thead>
            <tbody>
              {assets.data.items.map((a) => (
                <tr key={a.id} className={cn('hover:bg-surface-2/60', !a.isActive && 'opacity-60')}>
                  <Td>
                    <Link to={`/assets/${a.id}`} className="block min-w-0">
                      <span className="block truncate font-medium text-ink hover:underline">{a.name ?? a.value}</span>
                      <span className="block truncate text-xs text-muted">
                        {a.value} · {a.type === 'DOMAIN' ? 'Dominio' : 'IP'}
                        {!a.isActive ? ' · inactivo' : ''}
                      </span>
                    </Link>
                  </Td>
                  <Td>
                    <span className="flex items-center gap-2">
                      <GradeBadge grade={a.grade} size="sm" />
                      <span className="tabular font-semibold">{a.score ?? <span className="text-xs font-normal text-muted">Sin evaluar</span>}</span>
                    </span>
                  </Td>
                  <Td className="hidden md:table-cell">
                    <SeverityChips counts={a.bySeverity} />
                  </Td>
                  <Td className="hidden text-ink-2 sm:table-cell">{a.lastScannedAt ? timeAgo(a.lastScannedAt) : <span className="text-muted">Nunca</span>}</Td>
                  <Td className="text-right">
                    <div className="flex justify-end gap-1">
                      {canEdit ? (
                        <Button size="sm" variant="secondary" icon={<Radar className="size-3.5" />} onClick={() => audit(a)} disabled={!a.isActive || requestScan.isPending} title="Encola puertos, cabeceras, TLS y rutas sensibles">
                          Auditar
                        </Button>
                      ) : null}
                      <Link to={`/assets/${a.id}`} className="inline-flex h-8 items-center rounded-lg px-3 text-[13px] font-medium text-ink-2 hover:bg-surface-2 hover:text-ink">
                        Detalle
                      </Link>
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <CreateAssetModal open={open} onClose={() => setOpen(false)} onCreated={(name) => setNotice({ kind: 'success', text: `Activo ${name} registrado. Lanza una auditoría para evaluarlo.` })} />
    </>
  );
}

function SeverityChips({ counts }: { counts: DashboardAsset['bySeverity'] }) {
  const entries = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).filter((s) => counts[s] > 0);
  if (entries.length === 0) return <span className="text-xs text-muted">Ninguno</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {entries.map((s) => {
        const Icon = SEVERITY_STYLE[s].icon;
        return (
          <span key={s} className={cn('inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-semibold', SEVERITY_STYLE[s].chip)} title={SEVERITY_LABEL[s]}>
            <Icon className="size-3" aria-hidden />
            {counts[s]}
          </span>
        );
      })}
    </span>
  );
}

function CreateAssetModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (name: string) => void }) {
  const create = useCreateAsset();
  const [value, setValue] = useState('');
  const [name, setName] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setValue('');
    setName('');
    setAuthorized(false);
    setError(null);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const asset = await create.mutateAsync({ value: value.trim(), name: name.trim() || undefined, authorizationConfirmed: true });
      onCreated(asset.name ?? asset.value);
      reset();
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo registrar el activo.');
    }
  };

  return (
    <Modal
      open={open}
      onClose={() => {
        reset();
        onClose();
      }}
      title="Registrar activo"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancelar</Button>
          <Button type="submit" form="create-asset" loading={create.isPending} disabled={!authorized || !value.trim()}>Registrar</Button>
        </>
      }
    >
      <form id="create-asset" onSubmit={submit} className="space-y-4">
        <div>
          <Label htmlFor="asset-value">Dominio o IP pública</Label>
          <Input id="asset-value" required autoFocus placeholder="www.mi-empresa.com" value={value} onChange={(e) => setValue(e.target.value)} />
          <p className="mt-1 text-xs text-muted">Se normaliza automáticamente: puedes pegar una URL completa.</p>
        </div>
        <div>
          <Label htmlFor="asset-name" hint="(opcional)">Nombre</Label>
          <Input id="asset-name" placeholder="Sitio web corporativo" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <label className="flex items-start gap-3 rounded-lg border border-border bg-surface-2/60 p-3 text-sm">
          <input type="checkbox" className="mt-0.5 size-4 accent-accent" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          <span className="text-ink-2">
            <ShieldCheck className="mr-1 inline size-4 text-accent" aria-hidden />
            Confirmo que mi organización es propietaria de este activo o está expresamente autorizada a analizarlo.
          </span>
        </label>
        {error ? <Alert kind="error">{error}</Alert> : null}
      </form>
    </Modal>
  );
}
