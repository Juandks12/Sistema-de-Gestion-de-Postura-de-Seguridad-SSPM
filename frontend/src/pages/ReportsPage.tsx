import { FileBarChart, FileDown, FileText } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useReportDownload } from '@/hooks/useReportDownload';
import { Alert } from '@/components/ui/Alert';
import { GradeBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Label, Select } from '@/components/ui/Field';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import { useDashboardAssets, useReports } from '@/hooks/queries';
import { fileSize, formatDateTime, timeAgo } from '@/lib/format';
import type { ReportType } from '@/lib/types';

const REPORTS: Array<{ type: ReportType; title: string; audience: string; description: string; icon: typeof FileText }> = [
  {
    type: 'EXECUTIVE',
    title: 'Reporte ejecutivo',
    audience: 'Para gerencia y dirección',
    description: 'Security Score con su tendencia, evolución de los últimos 30 días, principales riesgos en lenguaje de negocio y acciones priorizadas.',
    icon: FileBarChart,
  },
  {
    type: 'TECHNICAL',
    title: 'Reporte técnico',
    audience: 'Para el equipo de TI y desarrollo',
    description: 'Detalle por activo: fecha de cada escaneo, puertos expuestos y todos los hallazgos abiertos con evidencia y recomendación de mitigación.',
    icon: FileText,
  },
];

export function ReportsPage() {
  const assets = useDashboardAssets();
  const reports = useReports();
  const { download, busy, error } = useReportDownload();
  const [scope, setScope] = useState('');

  const items = reports.data?.items ?? [];

  return (
    <>
      <PageHeader title="Reportes" description="Genera reportes en PDF con los datos vigentes, de toda la organización o de un activo concreto." />

      <div className="mb-4 max-w-sm">
        <Label htmlFor="r-scope">Alcance</Label>
        <Select id="r-scope" value={scope} onChange={(e) => setScope(e.target.value)}>
          <option value="">Toda la organización</option>
          {(assets.data?.items ?? []).map((a) => (
            <option key={a.id} value={a.id}>{a.name ? `${a.name} (${a.value})` : a.value}</option>
          ))}
        </Select>
      </div>
      {error ? <Alert kind="error" className="mb-4">{error}</Alert> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {REPORTS.map((r) => (
          <Card key={r.type}>
            <CardBody className="flex h-full flex-col pt-5">
              <div className="flex items-start gap-3">
                <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-accent/12 text-accent-strong">
                  <r.icon className="size-5" aria-hidden />
                </span>
                <div>
                  <h2 className="text-[15px] font-semibold text-ink">{r.title}</h2>
                  <p className="text-xs text-muted">{r.audience}</p>
                </div>
              </div>
              <p className="mt-3 flex-1 text-sm text-ink-2">{r.description}</p>
              <div className="mt-4">
                <Button
                  icon={<FileDown className="size-4" />}
                  loading={busy === r.type}
                  disabled={busy !== null && busy !== r.type}
                  onClick={() => download(r.type, scope || undefined)}
                >
                  Descargar PDF
                </Button>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>

      <Card className="mt-4">
        <CardHeader title="Historial" subtitle="Últimos reportes generados en la organización" />
        {reports.isPending ? (
          <div className="space-y-3 px-5 pb-5">{[0, 1].map((i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : items.length === 0 ? (
          <EmptyState icon={FileText} title="Aún no se ha generado ningún reporte" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Tipo</Th>
                <Th>Alcance</Th>
                <Th>Postura</Th>
                <Th className="hidden md:table-cell">Generado por</Th>
                <Th className="hidden sm:table-cell">Fecha</Th>
                <Th className="hidden lg:table-cell">Tamaño</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <Td className="font-medium text-ink">{r.type === 'EXECUTIVE' ? 'Ejecutivo' : 'Técnico'}</Td>
                  <Td className="text-ink-2">
                    {r.asset ? <Link to={`/assets/${r.asset.id}`} className="hover:underline">{r.asset.name ?? r.asset.value}</Link> : 'Organización'}
                  </Td>
                  <Td>
                    <span className="inline-flex items-center gap-2">
                      <GradeBadge grade={r.grade} size="sm" />
                      <span className="tabular text-ink-2">{r.score ?? '—'}</span>
                      <span className="hidden text-xs text-muted xl:inline">· {r.openFindings} abiertos</span>
                    </span>
                  </Td>
                  <Td className="hidden text-ink-2 md:table-cell">{r.generatedBy?.fullName ?? '—'}</Td>
                  <Td className="hidden whitespace-nowrap text-ink-2 sm:table-cell" title={formatDateTime(r.createdAt)}>{timeAgo(r.createdAt)}</Td>
                  <Td className="tabular hidden text-ink-2 lg:table-cell">{r.pages} pág. · {fileSize(r.sizeBytes)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
