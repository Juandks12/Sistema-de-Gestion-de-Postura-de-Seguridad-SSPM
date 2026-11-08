import { CheckCircle2, FileBarChart, FileDown, FileText, FlaskConical, Scale } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useReportDownload } from '@/hooks/useReportDownload';
import { Alert } from '@/components/ui/Alert';
import { GradeBadge, Pill } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { ExecutiveSummaryCard } from '@/components/ExecutiveSummaryCard';
import { Label, Select } from '@/components/ui/Field';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import {
  useComplianceOverview,
  useDashboardAssets,
  useReports,
  useThreatLabSummary,
} from '@/hooks/queries';
import { fileSize, formatDateTime, timeAgo } from '@/lib/format';
import type { ReportType } from '@/lib/types';

const REPORTS: Array<{
  type: ReportType;
  title: string;
  audience: string;
  description: string;
  highlights: string[];
  icon: typeof FileText;
}> = [
  {
    type: 'EXECUTIVE',
    title: 'Reporte ejecutivo (GRC + 360° + Threat Lab)',
    audience: 'Para gerencia, directorio, CISO y oficiales de cumplimiento',
    description:
      'Security Score con tendencia de 30 días, matriz de cumplimiento normativo (ISO 27001, PCI-DSS, SOC 2, NIST CSF, CIS Controls), telemetría del Laboratorio Forense de Malware/Phishing y evolución de Diagnósticos Profundos 360°.',
    highlights: [
      'Matriz GRC (5 marcos normativos)',
      'Telemetría Threat & Malware Lab',
      'Evolución Diagnóstico 360°',
    ],
    icon: FileBarChart,
  },
  {
    type: 'TECHNICAL',
    title: 'Reporte técnico forense y remediación',
    audience: 'Para ingeniería de seguridad, TI, DevSecOps y auditores técnicos',
    description:
      'Detalle exhaustivo por activo: puertos expuestos, evidencias crudas, referencias taxonómicas (CWE, OWASP, MITRE ATT&CK), controles normativos impactados y guías de remediación paso a paso.',
    highlights: [
      'Taxonomía CWE / OWASP / MITRE ATT&CK',
      'Controles GRC por hallazgo',
      'Evidencia técnica y remediación',
    ],
    icon: FileText,
  },
];

export function ReportsPage() {
  const assets = useDashboardAssets();
  const reports = useReports();
  const compliance = useComplianceOverview();
  const threatLab = useThreatLabSummary();
  const { download, busy, error } = useReportDownload();
  const [scope, setScope] = useState('');

  const items = reports.data?.items ?? [];

  return (
    <>
      <PageHeader
        title="Reportes Ejecutivos, Técnicos y GRC"
        description="Genera reportes en PDF auditables con postura de seguridad, cumplimiento normativo (GRC), evolución 360° y telemetría forense de amenazas."
      />

      <div className="mb-4 flex flex-wrap items-end justify-between gap-4">
        <div className="w-full max-w-sm">
          <Label htmlFor="r-scope">Alcance del reporte</Label>
          <Select id="r-scope" value={scope} onChange={(e) => setScope(e.target.value)}>
            <option value="">Toda la organización</option>
            {(assets.data?.items ?? []).map((a) => (
              <option key={a.id} value={a.id}>{a.name ? `${a.name} (${a.value})` : a.value}</option>
            ))}
          </Select>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {compliance.data ? (
            <Link
              to="/compliance"
              className="flex items-center gap-2.5 rounded-lg border border-border bg-surface-1 px-3.5 py-2 text-xs transition-colors hover:border-accent/40"
            >
              <Scale className="size-4 text-accent" aria-hidden />
              <div>
                <span className=" block font-medium text-ink">
                  Cumplimiento GRC: {compliance.data.globalCompliancePercentage}%
                </span>
                <span className="text-muted">
                  {compliance.data.totalFrameworks} marcos · {compliance.data.totalEvaluatedControls} controles incluidos en PDF
                </span>
              </div>
            </Link>
          ) : null}
          {threatLab.data ? (
            <Link
              to="/threat-lab"
              className="flex items-center gap-2.5 rounded-lg border border-border bg-surface-1 px-3.5 py-2 text-xs transition-colors hover:border-accent/40"
            >
              <FlaskConical className="size-4 text-accent" aria-hidden />
              <div>
                <span className="block font-medium text-ink">
                  Threat Lab: {threatLab.data.total} análisis forenses
                </span>
                <span className="text-muted">
                  {threatLab.data.byVerdict.MALICIOUS} maliciosos · {threatLab.data.promotedCount} promovidos a hallazgos
                </span>
              </div>
            </Link>
          ) : null}
        </div>
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
              <div className="mt-3 flex flex-wrap gap-1.5">
                {r.highlights.map((h) => (
                  <Pill key={h} className="inline-flex items-center gap-1 text-xs">
                    <CheckCircle2 className="size-3 text-accent" aria-hidden />
                    {h}
                  </Pill>
                ))}
              </div>
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

      <div className="mt-4">
        <ExecutiveSummaryCard
          assetId={scope || undefined}
          title={scope ? 'Resumen Ejecutivo del Activo' : 'Resumen Ejecutivo de la Organización'}
        />
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
