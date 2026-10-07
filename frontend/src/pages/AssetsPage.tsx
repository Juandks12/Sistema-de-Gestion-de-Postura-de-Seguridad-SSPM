import { Download, Plus, Radar, Server, ShieldCheck, ShieldQuestion, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { DeleteAssetModal } from '@/components/DeleteAssetModal';
import { Alert } from '@/components/ui/Alert';
import { CriticalityBadge, GradeBadge } from '@/components/ui/Badge';
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
import { ApiError, downloadFile } from '@/lib/api';
import { cn } from '@/lib/cn';
import { SEVERITY_LABEL, timeAgo } from '@/lib/format';
import type { Asset, AssetCriticality, DashboardAsset } from '@/lib/types';

export function AssetsPage() {
  const { canEdit, hasRole } = useAuth();
  const assets = useDashboardAssets();
  const [open, setOpen] = useState(false);
  const [assetToDelete, setAssetToDelete] = useState<DashboardAsset | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [notice, setNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const requestScan = useRequestScan();
  const navigate = useNavigate();
  const verificationRequired = assets.data?.verificationRequired ?? true;

  const handleExport = async () => {
    setDownloading(true);
    try {
      await downloadFile('/assets/export?format=csv', `assets-${new Date().toISOString().slice(0, 10)}.csv`);
    } catch (err) {
      console.error('Export error:', err);
    } finally {
      setDownloading(false);
    }
  };

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
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              icon={<Download className="size-4" />}
              onClick={handleExport}
              loading={downloading}
            >
              Exportar CSV
            </Button>
            {canEdit ? (
              <Button icon={<Plus className="size-4" />} onClick={() => setOpen(true)}>
                Registrar activo
              </Button>
            ) : null}
          </div>
        }
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
                      <div className="flex items-center gap-2">
                        <span className="truncate font-medium text-ink hover:underline">{a.name ?? a.value}</span>
                        {a.criticality ? <CriticalityBadge criticality={a.criticality} /> : null}
                      </div>
                      <span className="block truncate text-xs text-muted">
                        {a.value} · {a.type === 'DOMAIN' ? 'Dominio' : 'IP'}
                        {!a.isActive ? ' · inactivo' : ''}
                      </span>
                      <div className="mt-1 flex flex-wrap items-center gap-1.5">
                        {!a.verified ? (
                          <span className="inline-flex items-center gap-1 rounded-md bg-warning/18 px-1.5 py-0.5 text-xs font-medium text-[#8a5b00] dark:text-warning">
                            <ShieldQuestion className="size-3" aria-hidden /> Sin verificar
                          </span>
                        ) : null}
                        {a.tags?.map((t) => (
                          <span key={t} className="rounded-md bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">
                            #{t}
                          </span>
                        ))}
                      </div>
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
                        <Button size="sm" variant="secondary" icon={<Radar className="size-3.5" />} onClick={() => audit(a)}
                          disabled={!a.isActive || (verificationRequired && !a.verified) || requestScan.isPending}
                          title={verificationRequired && !a.verified ? 'Verifica la propiedad del activo para poder escanearlo' : 'Encola puertos, cabeceras, TLS y rutas sensibles'}
                        >
                          Auditar
                        </Button>
                      ) : null}
                      <Link to={`/assets/${a.id}`} className="inline-flex h-8 items-center rounded-lg px-3 text-[13px] font-medium text-ink-2 hover:bg-surface-2 hover:text-ink">
                        Detalle
                      </Link>
                      {hasRole('ADMIN') ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          className="text-muted hover:bg-critical/10 hover:text-critical"
                          icon={<Trash2 className="size-3.5" />}
                          onClick={() => setAssetToDelete(a)}
                          title="Eliminar activo y registrar auditoría"
                        >
                          <span className="sr-only">Eliminar</span>
                        </Button>
                      ) : null}
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <CreateAssetModal
        open={open}
        onClose={() => setOpen(false)}
        onCreated={(asset) =>
          asset.verifiedAt
            ? setNotice({ kind: 'success', text: `Activo ${asset.name ?? asset.value} registrado y ya verificado por su dominio superior. Lanza una auditoría para evaluarlo.` })
            : navigate(`/assets/${asset.id}`)
        }
      />

      <DeleteAssetModal
        open={!!assetToDelete}
        asset={assetToDelete}
        onClose={() => setAssetToDelete(null)}
        onDeleted={(label) =>
          setNotice({
            kind: 'success',
            text: `Activo ${label} eliminado. Su presencia y balance de acciones quedaron preservados en la auditoría.`,
          })
        }
      />
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

function CreateAssetModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (asset: Asset) => void }) {
  const create = useCreateAsset();
  const [value, setValue] = useState('');
  const [name, setName] = useState('');
  const [criticality, setCriticality] = useState<AssetCriticality>('MEDIUM');
  const [tags, setTags] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setValue('');
    setName('');
    setCriticality('MEDIUM');
    setTags('');
    setAuthorized(false);
    setError(null);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const parsedTags = tags
        .split(',')
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean);
      const asset = await create.mutateAsync({
        value: value.trim(),
        name: name.trim() || undefined,
        criticality,
        tags: parsedTags.length > 0 ? parsedTags : undefined,
        authorizationConfirmed: true,
      });
      onCreated(asset);
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
        <div>
          <Label htmlFor="asset-criticality">Criticidad para el negocio</Label>
          <select
            id="asset-criticality"
            className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink focus:border-accent focus:outline-none"
            value={criticality}
            onChange={(e) => setCriticality(e.target.value as AssetCriticality)}
          >
            <option value="CRITICAL">Crítico (Ponderación 1.5x - Producción, core, datos sensibles)</option>
            <option value="HIGH">Alto (Ponderación 1.25x - Portales clave, servicios expuestos)</option>
            <option value="MEDIUM">Medio (Ponderación 1.0x - Activo estándar / infraestructura general)</option>
            <option value="LOW">Bajo (Ponderación 0.75x - Entornos auxiliares, staging, dev)</option>
          </select>
          <p className="mt-1 text-xs text-muted">Pondera el impacto en el Security Score según el riesgo del negocio.</p>
        </div>
        <div>
          <Label htmlFor="asset-tags" hint="(opcional)">Etiquetas (separadas por comas)</Label>
          <Input id="asset-tags" placeholder="produccion, aws, pagos" value={tags} onChange={(e) => setTags(e.target.value)} />
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
