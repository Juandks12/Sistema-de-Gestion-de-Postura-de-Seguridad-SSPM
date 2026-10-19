import {
  AlertTriangle,
  Award,
  BookOpen,
  CheckCircle2,
  Download,
  ExternalLink,
  Layers,
  Search,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Alert } from '@/components/ui/Alert';
import { SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input, Select } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { StatTile } from '@/components/ui/StatTile';
import { Table, Td, Th } from '@/components/ui/Table';
import { useComplianceFramework, useComplianceOverview } from '@/hooks/queries';
import { downloadFile } from '@/lib/api';
import { cn } from '@/lib/cn';
import type {
  ComplianceFramework,
  ControlEvaluationResult,
} from '@/lib/types';

const FRAMEWORK_ORDER: ComplianceFramework[] = [
  'ISO_27001',
  'PCI_DSS',
  'SOC_2',
  'NIST_CSF',
  'CIS_CONTROLS',
];

export function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFramework>('ISO_27001');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'COMPLIANT' | 'NON_COMPLIANT'>('ALL');
  const [domainFilter, setDomainFilter] = useState<string>('ALL');
  const [selectedControl, setSelectedControl] = useState<ControlEvaluationResult | null>(null);
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const overviewQuery = useComplianceOverview();
  const frameworkQuery = useComplianceFramework(selectedFramework);

  const overview = overviewQuery.data;
  const frameworkData = frameworkQuery.data;

  const controls = frameworkData?.controls ?? [];

  // Extraer dominios únicos para el filtro del marco seleccionado
  const availableDomains = Array.from(new Set(controls.map((item) => item.control.domain))).sort();

  // Controles filtrados
  const filteredControls = controls.filter((item) => {
    if (statusFilter !== 'ALL' && item.status !== statusFilter) {
      return false;
    }
    if (domainFilter !== 'ALL' && item.control.domain !== domainFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchCode = item.control.code.toLowerCase().includes(q);
      const matchTitle = item.control.title.toLowerCase().includes(q);
      const matchDomain = item.control.domain.toLowerCase().includes(q);
      const matchDesc = item.control.description.toLowerCase().includes(q);
      if (!matchCode && !matchTitle && !matchDomain && !matchDesc) {
        return false;
      }
    }
    return true;
  });

  const handleExportCsv = async () => {
    try {
      setIsExporting(true);
      setExportError(null);
      const filename = `matriz-cumplimiento-${selectedFramework.toLowerCase().replace(/_/g, '-')}-${new Date()
        .toISOString()
        .slice(0, 10)}.csv`;
      await downloadFile(`/compliance/export?framework=${selectedFramework}`, filename);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Error al exportar la matriz CSV');
    } finally {
      setIsExporting(false);
    }
  };

  const getScoreColor = (pct: number) => {
    if (pct >= 85) return 'text-good-text bg-good/12 border-good/25';
    if (pct >= 70) return 'text-amber-500 bg-amber-500/12 border-amber-500/25';
    return 'text-critical bg-critical/12 border-critical/25';
  };

  const getProgressBarColor = (pct: number) => {
    if (pct >= 85) return 'bg-good';
    if (pct >= 70) return 'bg-amber-500';
    return 'bg-critical';
  };

  return (
    <>
      <PageHeader
        title="Cumplimiento Normativo"
        description="Mapeo y evaluación continua de la postura de seguridad contra los principales marcos y estándares de la industria."
        actions={
          <Button
            icon={<Download className="size-4" />}
            loading={isExporting}
            onClick={handleExportCsv}
          >
            Exportar Matriz (CSV)
          </Button>
        }
      />

      {exportError ? (
        <Alert kind="error" className="mb-4">
          {exportError}
        </Alert>
      ) : null}

      {/* Métricas Globales */}
      <section className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4" aria-label="Métricas de Cumplimiento">
        <div className="rounded-card border border-border bg-surface p-4 flex items-center gap-4">
          <div
            className={cn(
              'flex size-14 shrink-0 flex-col items-center justify-center rounded-xl border font-bold',
              overview ? getScoreColor(overview.globalCompliancePercentage) : 'border-border bg-surface-2 text-ink',
            )}
          >
            <span className="text-xl leading-none">{overview?.globalCompliancePercentage ?? 0}%</span>
            <span className="text-[10px] tracking-wide uppercase font-medium mt-0.5">Global</span>
          </div>
          <div>
            <p className="text-sm font-medium text-ink">Conformidad General</p>
            <p className="text-xs text-muted mt-0.5">
              Promedio ponderado en 5 marcos normativos
            </p>
          </div>
        </div>

        <StatTile
          label="Marcos Auditados"
          value={overview?.totalFrameworks ?? 5}
          hint="ISO 27001, PCI-DSS, SOC 2, NIST, CIS"
          icon={Layers}
        />

        <StatTile
          label="Controles Evaluados"
          value={overview?.totalEvaluatedControls ?? 0}
          hint="Requisitos técnicos correlacionados"
          icon={Award}
        />

        <StatTile
          label="Prioridades de Remediación"
          value={overview?.topFailingControls.length ?? 0}
          hint="Controles con hallazgos activos"
          tone={overview && overview.topFailingControls.length > 0 ? 'critical' : 'default'}
          icon={ShieldAlert}
        />
      </section>

      {/* Selector de Marcos Normativos */}
      <section className="mb-6" aria-label="Seleccionar Marco Regulatorio">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted">
            Marcos de Seguridad Soportados
          </h2>
          <span className="text-xs text-muted">Selecciona un marco para auditar sus controles</span>
        </div>

        {overviewQuery.isLoading ? (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3 lg:grid-cols-5">
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} className="h-32 rounded-card" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {FRAMEWORK_ORDER.map((fwKey) => {
              const summary = overview?.frameworks.find((f) => f.metadata.id === fwKey);
              if (!summary) return null;
              const isSelected = selectedFramework === fwKey;
              const pct = summary.compliancePercentage;

              return (
                <button
                  type="button"
                  key={fwKey}
                  onClick={() => {
                    setSelectedFramework(fwKey);
                    setStatusFilter('ALL');
                    setDomainFilter('ALL');
                    setSearchQuery('');
                  }}
                  className={cn(
                    'flex flex-col justify-between rounded-card border bg-surface p-4 text-left transition-all',
                    isSelected
                      ? 'border-accent ring-2 ring-accent/30 shadow-sm'
                      : 'border-border hover:border-accent/50 hover:bg-surface-2/40',
                  )}
                >
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span className="text-[11px] font-semibold uppercase tracking-wider text-muted">
                        {summary.metadata.authority}
                      </span>
                      <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] font-medium text-ink-2">
                        {summary.metadata.version}
                      </span>
                    </div>
                    <h3 className="text-sm font-semibold text-ink line-clamp-1" title={summary.metadata.name}>
                      {summary.metadata.name}
                    </h3>
                  </div>

                  <div className="mt-4">
                    <div className="flex items-baseline justify-between mb-1">
                      <span className="text-lg font-bold text-ink">{pct}%</span>
                      <span className="text-xs text-muted">
                        {summary.passedControls}/{summary.totalControls} conformes
                      </span>
                    </div>

                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
                      <div
                        className={cn('h-full transition-all duration-500', getProgressBarColor(pct))}
                        style={{ width: `${pct}%` }}
                      />
                    </div>

                    <div className="mt-2.5 flex items-center justify-between text-xs">
                      {summary.failedControls > 0 ? (
                        <span className="inline-flex items-center gap-1 font-medium text-critical">
                          <XCircle className="size-3.5" />
                          {summary.failedControls} incumplido{summary.failedControls > 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 font-medium text-good-text">
                          <CheckCircle2 className="size-3.5" />
                          100% conforme
                        </span>
                      )}

                      {summary.worstSeverity ? (
                        <SeverityBadge severity={summary.worstSeverity} compact />
                      ) : null}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </section>

      {/* Matriz Detallada del Marco Seleccionado */}
      <Card className="mb-6">
        <CardHeader
          title={
            <div className="flex flex-wrap items-center gap-2">
              <span>{frameworkData?.metadata.name ?? selectedFramework}</span>
              {frameworkData?.metadata.version ? (
                <span className="rounded-md bg-accent/10 px-2 py-0.5 text-xs font-semibold text-accent-strong">
                  {frameworkData.metadata.version}
                </span>
              ) : null}
            </div>
          }
          subtitle={frameworkData?.metadata.description}
          action={
            frameworkData ? (
              <div className="flex items-center gap-2 text-xs">
                <span className="rounded-md bg-good/12 px-2.5 py-1 font-medium text-good-text">
                  {frameworkData.summary.passedControls} Cumplidos
                </span>
                <span
                  className={cn(
                    'rounded-md px-2.5 py-1 font-medium',
                    frameworkData.summary.failedControls > 0
                      ? 'bg-critical/12 text-critical'
                      : 'bg-surface-2 text-muted',
                  )}
                >
                  {frameworkData.summary.failedControls} Incumplidos
                </span>
              </div>
            ) : null
          }
        />

        {/* Barra de Filtros */}
        <div className="border-b border-line px-5 py-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" />
              <Input
                placeholder="Buscar control por código, título o requisito..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 text-xs"
              />
            </div>

            <Select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'ALL' | 'COMPLIANT' | 'NON_COMPLIANT')}
              className="text-xs"
            >
              <option value="ALL">Todos los estados</option>
              <option value="NON_COMPLIANT">Solo Incumplidos</option>
              <option value="COMPLIANT">Solo Cumplidos</option>
            </Select>

            <Select
              value={domainFilter}
              onChange={(e) => setDomainFilter(e.target.value)}
              className="text-xs"
            >
              <option value="ALL">Todos los dominios</option>
              {availableDomains.map((dom) => (
                <option key={dom} value={dom}>
                  {dom}
                </option>
              ))}
            </Select>
          </div>
        </div>

        {/* Tabla de Controles */}
        <CardBody className="p-0">
          {frameworkQuery.isLoading ? (
            <div className="space-y-2 p-5">
              {[1, 2, 3, 4, 5].map((i) => (
                <Skeleton key={i} className="h-12 w-full rounded" />
              ))}
            </div>
          ) : filteredControls.length === 0 ? (
            <div className="p-8">
              <EmptyState
                icon={BookOpen}
                title="No se encontraron controles"
                description="Intenta cambiar los filtros de búsqueda o seleccionar otro marco normativo."
              />
            </div>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th className="w-28">Código</Th>
                  <Th>Control / Requisito</Th>
                  <Th className="w-36">Dominio</Th>
                  <Th className="w-28 text-center">Estado</Th>
                  <Th className="w-32">Peor Severidad</Th>
                  <Th className="w-28 text-center">Hallazgos</Th>
                  <Th className="w-28 text-center">Activos</Th>
                  <Th className="w-24 text-right">Acción</Th>
                </tr>
              </thead>
              <tbody>
                {filteredControls.map((item) => {
                  const isCompliant = item.status === 'COMPLIANT';

                  return (
                    <tr
                      key={item.control.id}
                      className={cn(
                        'transition-colors hover:bg-surface-2/40',
                        !isCompliant && 'bg-critical/[0.02]',
                      )}
                    >
                      <Td className="font-mono text-xs font-semibold text-ink">
                        {item.control.code}
                      </Td>
                      <Td>
                        <p className="font-medium text-ink">{item.control.title}</p>
                        <p className="text-xs text-muted line-clamp-1 mt-0.5">
                          {item.control.description}
                        </p>
                      </Td>
                      <Td>
                        <span className="inline-block rounded bg-surface-2 px-2 py-0.5 text-xs text-ink-2">
                          {item.control.domain}
                        </span>
                      </Td>
                      <Td className="text-center">
                        {isCompliant ? (
                          <span className="inline-flex items-center gap-1 rounded-md bg-good/12 px-2 py-0.5 text-xs font-semibold text-good-text">
                            <CheckCircle2 className="size-3" />
                            Cumplido
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-md bg-critical/10 px-2 py-0.5 text-xs font-semibold text-critical">
                            <XCircle className="size-3" />
                            Incumplido
                          </span>
                        )}
                      </Td>
                      <Td>
                        {item.worstSeverity ? (
                          <SeverityBadge severity={item.worstSeverity} />
                        ) : (
                          <span className="text-xs text-muted">—</span>
                        )}
                      </Td>
                      <Td className="text-center">
                        {item.failingFindingsCount > 0 ? (
                          <span className="rounded-full bg-critical/10 px-2 py-0.5 text-xs font-bold text-critical">
                            {item.failingFindingsCount}
                          </span>
                        ) : (
                          <span className="text-xs text-muted">0</span>
                        )}
                      </Td>
                      <Td className="text-center">
                        {item.affectedAssetsCount > 0 ? (
                          <span className="rounded-full bg-surface-2 px-2 py-0.5 text-xs font-semibold text-ink">
                            {item.affectedAssetsCount}
                          </span>
                        ) : (
                          <span className="text-xs text-muted">0</span>
                        )}
                      </Td>
                      <Td className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedControl(item)}
                        >
                          Auditar
                        </Button>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          )}
        </CardBody>
      </Card>

      {/* Sección Inferior: Prioridades de Remediación Globales */}
      {overview && overview.topFailingControls.length > 0 ? (
        <Card>
          <CardHeader
            title={
              <div className="flex items-center gap-2">
                <AlertTriangle className="size-4 text-amber-500" />
                <span>Principales Prioridades de Remediación Normativa</span>
              </div>
            }
            subtitle="Controles con mayor cantidad de hallazgos abiertos que impactan el nivel de cumplimiento de tu organización."
          />
          <CardBody className="p-0">
            <Table>
              <thead>
                <tr>
                  <Th className="w-32">Marco</Th>
                  <Th className="w-24">Código</Th>
                  <Th>Control Afectado</Th>
                  <Th className="w-36">Dominio</Th>
                  <Th className="w-28">Severidad</Th>
                  <Th className="w-28 text-center">Hallazgos</Th>
                  <Th className="w-28 text-center">Activos</Th>
                  <Th className="w-24 text-right">Ir al Marco</Th>
                </tr>
              </thead>
              <tbody>
                {overview.topFailingControls.map((top, idx) => (
                  <tr key={`${top.framework}-${top.code}-${idx}`} className="hover:bg-surface-2/40">
                    <Td className="text-xs font-medium text-ink-2">
                      {top.framework.replace(/_/g, ' ')}
                    </Td>
                    <Td className="font-mono text-xs font-semibold text-ink">
                      {top.code}
                    </Td>
                    <Td className="font-medium text-ink">{top.title}</Td>
                    <Td className="text-xs text-muted">{top.domain}</Td>
                    <Td>
                      <SeverityBadge severity={top.worstSeverity} />
                    </Td>
                    <Td className="text-center font-bold text-critical">
                      {top.failingFindingsCount}
                    </Td>
                    <Td className="text-center font-medium text-ink">
                      {top.affectedAssetsCount}
                    </Td>
                    <Td className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setSelectedFramework(top.framework);
                          setSearchQuery(top.code);
                          window.scrollTo({ top: 400, behavior: 'smooth' });
                        }}
                      >
                        Ver
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </CardBody>
        </Card>
      ) : null}

      {/* Modal de Detalle de Control */}
      {selectedControl ? (
        <Modal
          open={Boolean(selectedControl)}
          onClose={() => setSelectedControl(null)}
          title={`Control ${selectedControl.control.code}: ${selectedControl.control.title}`}
          size="lg"
          footer={
            <Button variant="secondary" onClick={() => setSelectedControl(null)}>
              Cerrar
            </Button>
          }
        >
          <div className="space-y-4">
            {/* Cabecera del Control */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
              <div className="flex items-center gap-2">
                <span className="rounded bg-surface-2 px-2 py-0.5 text-xs font-semibold text-ink">
                  {selectedControl.control.framework.replace(/_/g, ' ')}
                </span>
                <span className="rounded bg-surface-2 px-2 py-0.5 text-xs text-ink-2">
                  {selectedControl.control.domain}
                </span>
              </div>
              <div>
                {selectedControl.status === 'COMPLIANT' ? (
                  <span className="inline-flex items-center gap-1 rounded-md bg-good/12 px-2.5 py-0.5 text-xs font-semibold text-good-text">
                    <CheckCircle2 className="size-3.5" />
                    Control Conforme
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 rounded-md bg-critical/10 px-2.5 py-0.5 text-xs font-semibold text-critical">
                    <XCircle className="size-3.5" />
                    Incumplido ({selectedControl.failingFindingsCount} hallazgos)
                  </span>
                )}
              </div>
            </div>

            {/* Requisito Normativo */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted mb-1">
                Requisito Oficial del Estándar
              </p>
              <div className="rounded-lg bg-surface-2 p-3 text-sm leading-relaxed text-ink">
                {selectedControl.control.description}
              </div>
            </div>

            {/* Reglas Técnicas Mapeadas */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted mb-1.5">
                Reglas de Detección Correlacionadas ({selectedControl.control.ruleIds.length})
              </p>
              <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto p-1">
                {selectedControl.control.ruleIds.map((ruleId) => {
                  const isTriggered = selectedControl.failingFindings.some((f) => f.ruleId === ruleId);
                  return (
                    <span
                      key={ruleId}
                      className={cn(
                        'rounded px-2 py-0.5 font-mono text-[11px] font-medium transition-colors',
                        isTriggered
                          ? 'bg-critical/15 text-critical border border-critical/30 font-semibold'
                          : 'bg-surface-2 text-muted',
                      )}
                    >
                      {ruleId}
                    </span>
                  );
                })}
              </div>
            </div>

            {/* Hallazgos Afectando el Control */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted mb-2">
                Evidencia de Auditoría ({selectedControl.failingFindings.length} hallazgos activos)
              </p>

              {selectedControl.status === 'COMPLIANT' ? (
                <div className="rounded-lg border border-good/20 bg-good/5 p-4 text-center">
                  <ShieldCheck className="mx-auto size-8 text-good mb-1.5" />
                  <p className="text-sm font-semibold text-ink">Control Conforme y Verificado</p>
                  <p className="text-xs text-muted mt-0.5">
                    No existen hallazgos abiertos o en progreso en los activos de tu organización que violen los requisitos de este control.
                  </p>
                </div>
              ) : (
                <div className="max-h-72 overflow-y-auto rounded-lg border border-border divide-y divide-line">
                  {selectedControl.failingFindings.map((finding) => (
                    <div key={finding.id} className="p-3 hover:bg-surface-2/40 transition-colors">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <SeverityBadge severity={finding.severity} compact />
                            <span className="font-mono text-xs font-semibold text-ink-2">
                              {finding.ruleId}
                            </span>
                            {finding.cvssScore ? (
                              <span className="text-[11px] font-medium text-muted">
                                CVSS {finding.cvssScore.toFixed(1)}
                              </span>
                            ) : null}
                          </div>
                          <p className="text-sm font-semibold text-ink">{finding.title}</p>
                          <p className="text-xs text-muted mt-0.5 truncate">
                            Ubicación: <code className="text-ink-2 font-mono">{finding.location}</code>
                          </p>
                        </div>
                        <Link
                          to={`/findings?assetId=${finding.assetId}`}
                          className="shrink-0 inline-flex items-center gap-1 rounded bg-surface-2 px-2 py-1 text-xs font-medium text-accent hover:bg-accent/10"
                          title="Ver en módulo de hallazgos"
                        >
                          <span>{finding.assetName ?? finding.assetValue}</span>
                          <ExternalLink className="size-3" />
                        </Link>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Modal>
      ) : null}
    </>
  );
}
