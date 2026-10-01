import { ArrowLeft, Radar, Server, ShieldAlert } from 'lucide-react';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { AssetVerificationCard } from '@/components/AssetVerificationCard';
import { DiscoveredHostsCard } from '@/components/DiscoveredHostsCard';
import { EmailSecurityCard } from '@/components/EmailSecurityCard';
import { ReportButtons } from '@/components/ReportButtons';
import { ScoreHistoryChart } from '@/components/charts/ScoreHistoryChart';
import { Alert } from '@/components/ui/Alert';
import { ScanStatusBadge, SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { PageHeader } from '@/components/ui/PageHeader';
import { ScoreHero } from '@/components/ui/ScoreHero';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import { useAssetVerification, useDashboardAsset, useRequestScan, useUpdateAsset } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { DOMAIN_ONLY_SCANS, SCAN_TYPE_HINT, SCAN_TYPE_LABEL, SEVERITY_LABEL, formatDateTime, timeAgo } from '@/lib/format';
import type { EmailSecuritySummary, ScanType } from '@/lib/types';

const SCAN_TYPES: ScanType[] = ['PORT_SCAN', 'WEB_HEADERS', 'SSL_CERT', 'SENSITIVE_PATHS', 'EMAIL_SECURITY', 'SUBDOMAIN_DISCOVERY'];

export function AssetDetailPage() {
  const { id = '' } = useParams();
  const { canEdit } = useAuth();
  const q = useDashboardAsset(id);
  const verification = useAssetVerification(id);
  const requestScan = useRequestScan();
  const update = useUpdateAsset();
  const [notice, setNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

  if (q.isPending) return <Skeleton className="h-64" />;
  if (q.isError || !q.data) return <EmptyState icon={Server} title="Activo no encontrado" action={<Link to="/assets" className="text-sm text-accent hover:underline">Volver a activos</Link>} />;

  const { asset, securityScore, history, findings, exposure, latestScans } = q.data;
  const inProgress = latestScans.some((s) => s.status === 'PENDING' || s.status === 'RUNNING');
  // Sin verificar no se puede escanear (a menos que el servidor lo tenga desactivado).
  const canScan = asset.isActive && (!!asset.verifiedAt || verification.data?.required === false);
  const isDomain = asset.type === 'DOMAIN';
  const scanTypes = SCAN_TYPES.filter((t) => isDomain || !DOMAIN_ONLY_SCANS.includes(t));
  const emailScan = latestScans.find((s) => s.type === 'EMAIL_SECURITY' && s.status === 'COMPLETED' && s.summary);
  const discoveryScan = latestScans.find((s) => s.type === 'SUBDOMAIN_DISCOVERY');
  const discovering = discoveryScan?.status === 'PENDING' || discoveryScan?.status === 'RUNNING';

  const run = async (type?: ScanType) => {
    setNotice(null);
    try {
      await requestScan.mutateAsync({ assetId: asset.id, type });
      setNotice({ kind: 'success', text: type ? `Escaneo de ${SCAN_TYPE_LABEL[type].toLowerCase()} encolado.` : 'Auditoría completa encolada.' });
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof ApiError ? err.message : 'No se pudo encolar el escaneo.' });
    }
  };

  return (
    <>
      <Link to="/assets" className="mb-3 inline-flex items-center gap-1 text-sm text-ink-2 hover:text-ink">
        <ArrowLeft className="size-4" aria-hidden /> Activos
      </Link>
      <PageHeader
        title={asset.name ?? asset.value}
        description={
          <>
            {asset.value} · {asset.type === 'DOMAIN' ? 'Dominio' : 'Dirección IP'} · registrado {timeAgo(asset.createdAt)}
            {!asset.isActive ? <span className="ml-2 rounded-md bg-surface-2 px-1.5 py-0.5 text-xs text-muted">Inactivo</span> : null}
          </>
        }
        actions={
          <>
            <ReportButtons assetId={asset.id} />
            {canEdit ? (
              <>
                <Button variant="secondary" size="md" onClick={() => update.mutate({ id: asset.id, isActive: !asset.isActive })} loading={update.isPending}>
                  {asset.isActive ? 'Desactivar' : 'Activar'}
                </Button>
                <Button
                  icon={<Radar className="size-4" />}
                  onClick={() => run()}
                  loading={requestScan.isPending}
                  disabled={!canScan}
                  title={asset.verifiedAt ? undefined : 'Verifica la propiedad del activo para poder escanearlo'}
                >
                  Auditoría completa
                </Button>
              </>
            ) : null}
          </>
        }
      />
      {notice ? <Alert kind={notice.kind} className="mb-4">{notice.text}</Alert> : null}
      <AssetVerificationCard assetId={asset.id} canEdit={canEdit} />
      {inProgress ? <Alert kind="info" className="mb-4">Hay escaneos en curso. Esta vista se actualiza automáticamente.</Alert> : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Security Score del activo" />
          <CardBody>
            <ScoreHero score={securityScore.score} grade={securityScore.grade} label={securityScore.label} description={securityScore.description} size="md" />
            {securityScore.scored ? (
              <div className="mt-5 border-t border-line pt-4">
                <p className="mb-2 text-xs font-semibold tracking-wide text-muted uppercase">Cómo se calcula</p>
                <ul className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
                  {securityScore.penalties.filter((p) => p.count > 0).map((p) => (
                    <li key={p.severity} className="flex items-center justify-between gap-2">
                      <span className="text-ink-2">
                        {p.count} × {SEVERITY_LABEL[p.severity].toLowerCase()} ({p.weight} pts)
                      </span>
                      <span className="tabular font-medium text-ink">−{p.penalty}{p.capped ? ' (tope)' : ''}</span>
                    </li>
                  ))}
                  {securityScore.totalPenalty === 0 ? <li className="text-ink-2">Sin penalizaciones: no hay hallazgos abiertos.</li> : null}
                </ul>
              </div>
            ) : null}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Escaneos" subtitle="Último de cada tipo" />
          <CardBody className="px-0 pb-2">
            <ul className="divide-y divide-line">
              {scanTypes.map((type) => {
                const last = latestScans.find((s) => s.type === type);
                return (
                  <li key={type} className="flex items-center gap-3 px-5 py-2.5">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-ink">{SCAN_TYPE_LABEL[type]}</p>
                      <p className="truncate text-xs text-muted" title={SCAN_TYPE_HINT[type]}>
                        {last ? (last.finishedAt ? timeAgo(last.finishedAt) : timeAgo(last.createdAt)) : 'Nunca ejecutado'} · {SCAN_TYPE_HINT[type]}
                      </p>
                    </div>
                    {last ? <ScanStatusBadge status={last.status} /> : null}
                    {canEdit && canScan ? (
                      <Button size="sm" variant="ghost" onClick={() => run(type)} disabled={requestScan.isPending} aria-label={`Ejecutar ${SCAN_TYPE_LABEL[type]}`}>
                        <Radar className="size-4" />
                      </Button>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          </CardBody>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Evolución del score" />
          <CardBody><ScoreHistoryChart points={history} height={200} /></CardBody>
        </Card>
        <Card>
          <CardHeader title="Superficie expuesta" subtitle={exposure.scannedAt ? `Puertos abiertos · ${timeAgo(exposure.scannedAt)}` : 'Sin escaneo de puertos'} />
          <CardBody className="px-0 pb-2">
            {exposure.openPorts.length === 0 ? (
              <p className="px-5 pb-3 text-sm text-muted">{exposure.scannedAt ? 'No se detectaron puertos abiertos.' : 'Ejecuta un escaneo de puertos para ver los servicios expuestos.'}</p>
            ) : (
              <ul className="divide-y divide-line">
                {exposure.openPorts.map((p) => (
                  <li key={`${p.protocol}-${p.port}`} className="flex items-center gap-3 px-5 py-2">
                    <span className="tabular w-16 shrink-0 text-sm font-semibold text-ink">{p.port}/{p.protocol}</span>
                    <span className="min-w-0 flex-1 truncate text-sm text-ink-2">{p.serviceName ?? '—'}{p.product ? ` · ${p.product}` : ''}{p.version ? ` ${p.version}` : ''}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>

      {isDomain ? (
        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="min-w-0 lg:col-span-2">
            <DiscoveredHostsCard
              assetId={asset.id}
              canEdit={canEdit}
              canScan={canScan}
              onRun={() => run('SUBDOMAIN_DISCOVERY')}
              running={discovering || requestScan.isPending}
              lastRunAt={discoveryScan?.finishedAt ?? null}
            />
          </div>
          {emailScan ? (
            <EmailSecurityCard summary={emailScan.summary as unknown as EmailSecuritySummary} finishedAt={emailScan.finishedAt} />
          ) : null}
        </div>
      ) : null}

      <Card className="mt-4">
        <CardHeader title="Hallazgos abiertos" subtitle={`${findings.open} en total`} action={<Link to={`/findings?assetId=${asset.id}`} className="text-sm font-medium text-accent hover:underline">Gestionar</Link>} />
        {findings.items.length === 0 ? (
          <EmptyState icon={ShieldAlert} title="Sin hallazgos abiertos" description={securityScore.scored ? 'Este activo no presenta exposiciones conocidas.' : 'Lanza una auditoría para evaluar el activo.'} />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Severidad</Th>
                <Th>Hallazgo</Th>
                <Th className="hidden md:table-cell">Ubicación</Th>
                <Th className="hidden sm:table-cell">Detectado</Th>
              </tr>
            </thead>
            <tbody>
              {findings.items.map((f) => (
                <tr key={f.id}>
                  <Td>
                        <span className="sm:hidden"><SeverityBadge severity={f.severity} compact /></span>
                        <span className="hidden sm:inline"><SeverityBadge severity={f.severity} /></span>
                      </Td>
                  <Td>
                    <p className="font-medium text-ink">{f.title}</p>
                    <p className="mt-0.5 line-clamp-2 text-xs text-ink-2">{f.recommendation}</p>
                  </Td>
                  <Td className="hidden max-w-[16rem] truncate text-ink-2 md:table-cell" title={f.location}>{f.location}</Td>
                  <Td className="hidden whitespace-nowrap text-ink-2 sm:table-cell" title={formatDateTime(f.firstSeenAt)}>{timeAgo(f.firstSeenAt)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
