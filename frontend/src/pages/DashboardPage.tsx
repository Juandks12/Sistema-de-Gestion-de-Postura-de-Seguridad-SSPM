import { Activity, Radar, Server, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { ScoreHistoryChart } from '@/components/charts/ScoreHistoryChart';
import { GradeBadge, ScanStatusBadge, SeverityBadge } from '@/components/ui/Badge';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { PageHeader } from '@/components/ui/PageHeader';
import { ScoreHero } from '@/components/ui/ScoreHero';
import { SeverityBars } from '@/components/ui/SeverityBars';
import { Skeleton } from '@/components/ui/Spinner';
import { StatTile } from '@/components/ui/StatTile';
import { useDashboardAssets, useOrgHistory, useOverview } from '@/hooks/queries';
import { SCAN_TYPE_LABEL, timeAgo, timeAgoShort } from '@/lib/format';
import { Button } from '@/components/ui/Button';
import { useNavigate } from 'react-router-dom';

export function DashboardPage() {
  const overview = useOverview();
  const history = useOrgHistory(30);
  const assets = useDashboardAssets();
  const navigate = useNavigate();

  if (overview.isPending) return <DashboardSkeleton />;
  if (overview.isError || !overview.data) {
    return <EmptyState icon={Activity} title="No se pudo cargar el dashboard" description={overview.error instanceof Error ? overview.error.message : undefined} />;
  }

  const o = overview.data;
  const s = o.securityScore;
  const worst = (assets.data?.items ?? []).filter((a) => a.score !== null).slice(0, 5);

  return (
    <>
      <PageHeader title="Vista general" description={`Actualizado ${timeAgo(o.generatedAt)} · ${s.scoredAssets} de ${s.totalAssets} activos evaluados`} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Security Score" subtitle="Postura de seguridad de la organización" />
          <CardBody>
            <ScoreHero score={s.score} grade={s.grade} label={s.label} description={s.description} delta={s.trend.sinceLastWeek} deltaLabel="frente a hace 7 días" />
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Hallazgos abiertos" subtitle={`${o.findings.open} en total`} action={<Link to="/findings" className="text-sm font-medium text-accent hover:underline">Ver todos</Link>} />
          <CardBody>
            <SeverityBars counts={o.findings.bySeverity} onSelect={(sev) => navigate(`/findings?severity=${sev}&status=OPEN`)} />
          </CardBody>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Activos monitoreados" value={o.assets.active} hint={o.assets.inactive ? `${o.assets.inactive} inactivos` : 'Todos activos'} icon={Server} />
        <StatTile label="Hallazgos críticos y altos" value={o.findings.bySeverity.CRITICAL + o.findings.bySeverity.HIGH} hint="Requieren acción prioritaria" icon={ShieldAlert} tone={o.findings.bySeverity.CRITICAL > 0 ? 'critical' : 'default'} />
        <StatTile label="Escaneos en curso" value={o.scans.inProgress} hint={`${o.scans.completedLast24h} completados en 24 h`} icon={Radar} tone={o.scans.inProgress > 0 ? 'accent' : 'default'} />
        <StatTile label="Último escaneo" value={o.scans.lastCompletedAt ? timeAgoShort(o.scans.lastCompletedAt) : '—'} hint={`${o.scans.last7Days.COMPLETED} completados en 7 días`} icon={Activity} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Evolución de la postura" subtitle="Security Score de la organización, últimos 30 días" />
          <CardBody>{history.isPending ? <Skeleton className="h-[220px]" /> : <ScoreHistoryChart points={history.data?.points ?? []} />}</CardBody>
        </Card>

        <Card>
          <CardHeader title="Activos con peor postura" action={<Link to="/assets" className="text-sm font-medium text-accent hover:underline">Ver activos</Link>} />
          <CardBody className="px-0 pb-2">
            {worst.length === 0 ? (
              <EmptyState icon={Server} title="Sin activos evaluados" description="Registra un activo y lanza una auditoría." action={<Button size="sm" onClick={() => navigate('/assets')}>Ir a activos</Button>} />
            ) : (
              <ul className="divide-y divide-line">
                {worst.map((a) => (
                  <li key={a.id}>
                    <Link to={`/assets/${a.id}`} className="flex items-center gap-3 px-5 py-2.5 hover:bg-surface-2">
                      <GradeBadge grade={a.grade} size="sm" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-ink">{a.name ?? a.value}</p>
                        <p className="truncate text-xs text-muted">{a.value}</p>
                      </div>
                      <span className="tabular text-sm font-semibold text-ink">{a.score}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader title="Hallazgos prioritarios" subtitle="Los de mayor puntuación CVSS que siguen abiertos" />
          <CardBody className="px-0 pb-2">
            {o.topFindings.length === 0 ? (
              <EmptyState icon={ShieldAlert} title="Sin hallazgos abiertos" description="Cuando un escaneo detecte un problema aparecerá aquí." />
            ) : (
              <ul className="divide-y divide-line">
                {o.topFindings.slice(0, 6).map((f) => (
                  <li key={f.id} className="flex items-start gap-3 px-5 py-3">
                    <SeverityBadge severity={f.severity} compact />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-ink">{f.title}</p>
                      <p className="truncate text-xs text-muted">
                        <Link to={`/assets/${f.asset.id}`} className="hover:underline">{f.asset.name ?? f.asset.value}</Link> · {f.location}
                      </p>
                    </div>
                    <span className="hidden text-xs text-muted sm:block">{timeAgo(f.lastSeenAt)}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Escaneos recientes" action={<Link to="/scans" className="text-sm font-medium text-accent hover:underline">Ver todos</Link>} />
          <CardBody className="px-0 pb-2">
            {o.recentScans.length === 0 ? (
              <EmptyState icon={Radar} title="Sin escaneos" />
            ) : (
              <ul className="divide-y divide-line">
                {o.recentScans.map((sc) => (
                  <li key={sc.id} className="flex items-center gap-3 px-5 py-2.5">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-ink">{SCAN_TYPE_LABEL[sc.type]}</p>
                      <p className="truncate text-xs text-muted">{sc.asset.name ?? sc.asset.value} · {timeAgo(sc.createdAt)}</p>
                    </div>
                    <ScanStatusBadge status={sc.status} />
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>
    </>
  );
}

function DashboardSkeleton() {
  return (
    <>
      <Skeleton className="mb-6 h-8 w-56" />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Skeleton className="h-52 lg:col-span-2" />
        <Skeleton className="h-52" />
      </div>
      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
    </>
  );
}
