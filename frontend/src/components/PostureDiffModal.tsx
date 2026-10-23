import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Globe,
  Layers,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';
import { SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/Modal';
import { Skeleton } from '@/components/ui/Spinner';
import { usePostureDiff } from '@/hooks/queries';
import { formatDateTime } from '@/lib/format';

interface PostureDiffModalProps {
  open: boolean;
  onClose: () => void;
  assetId: string;
  fromBatchId?: string;
  toBatchId?: string;
}

export function PostureDiffModal({
  open,
  onClose,
  assetId,
  fromBatchId,
  toBatchId,
}: PostureDiffModalProps) {
  const diffQuery = usePostureDiff(assetId, fromBatchId, toBatchId, open);

  const diff = diffQuery.data;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Comparativa de Postura de Seguridad (Diff Temporal)"
      size="xl"
      footer={
        <Button variant="secondary" onClick={onClose}>
          Cerrar
        </Button>
      }
    >
      {diffQuery.isLoading ? (
        <div className="space-y-4 py-4">
          <Skeleton className="h-20 w-full rounded-xl" />
          <Skeleton className="h-32 w-full rounded-xl" />
          <Skeleton className="h-40 w-full rounded-xl" />
        </div>
      ) : diffQuery.isError || !diff ? (
        <div className="rounded-xl border border-critical/30 bg-critical/5 p-4 text-sm text-critical">
          No se pudo calcular la comparativa temporal de postura o no se encontraron diagnósticos previos para contrastar.
        </div>
      ) : (
        <div className="space-y-5">
          {/* Resumen Ejecutivo */}
          <div className="rounded-xl border border-accent/20 bg-accent/5 p-4 text-ink">
            <div className="flex items-start gap-3">
              <ShieldCheck className="mt-0.5 size-5 shrink-0 text-accent" />
              <div>
                <h4 className="text-sm font-semibold text-accent">Resumen Ejecutivo del Diagnóstico</h4>
                <p className="mt-1 text-sm leading-relaxed text-ink-2">{diff.executiveSummary}</p>
                {diff.baselineDate && diff.comparisonDate ? (
                  <div className="mt-2 flex items-center gap-2 text-xs text-muted">
                    <Clock className="size-3.5" />
                    <span>
                      Comparando {formatDateTime(diff.baselineDate)} vs {formatDateTime(diff.comparisonDate)}
                    </span>
                  </div>
                ) : null}
              </div>
            </div>
          </div>

          {/* Comparativa de Score */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-border bg-surface-2 p-3 text-center">
              <span className="text-xs font-medium uppercase tracking-wider text-muted">Postura Inicial</span>
              <div className="mt-1 flex items-baseline justify-center gap-1.5">
                <span className="text-2xl font-bold text-ink">
                  {diff.scoreComparison.fromScore !== null ? diff.scoreComparison.fromScore : 'N/A'}
                </span>
                {diff.scoreComparison.fromGrade ? (
                  <span className="text-xs font-semibold text-muted">({diff.scoreComparison.fromGrade})</span>
                ) : null}
              </div>
            </div>

            <div className="flex items-center justify-center">
              <div className="flex items-center gap-2 rounded-full border border-border bg-surface px-3 py-1 shadow-sm">
                {diff.scoreComparison.delta !== null && diff.scoreComparison.delta > 0 ? (
                  <TrendingUp className="size-4 text-emerald-500" />
                ) : diff.scoreComparison.delta !== null && diff.scoreComparison.delta < 0 ? (
                  <TrendingDown className="size-4 text-rose-500" />
                ) : (
                  <ArrowRight className="size-4 text-muted" />
                )}
                <span
                  className={`text-sm font-bold ${
                    diff.scoreComparison.delta !== null && diff.scoreComparison.delta > 0
                      ? 'text-emerald-500'
                      : diff.scoreComparison.delta !== null && diff.scoreComparison.delta < 0
                        ? 'text-rose-500'
                        : 'text-muted'
                  }`}
                >
                  {diff.scoreComparison.delta !== null
                    ? `${diff.scoreComparison.delta > 0 ? '+' : ''}${diff.scoreComparison.delta} pts`
                    : 'Sin variación'}
                </span>
              </div>
            </div>

            <div className="rounded-xl border border-border bg-surface-2 p-3 text-center">
              <span className="text-xs font-medium uppercase tracking-wider text-muted">Postura Actual</span>
              <div className="mt-1 flex items-baseline justify-center gap-1.5">
                <span className="text-2xl font-bold text-ink">
                  {diff.scoreComparison.toScore !== null ? diff.scoreComparison.toScore : 'N/A'}
                </span>
                {diff.scoreComparison.toGrade ? (
                  <span className="text-xs font-semibold text-accent">({diff.scoreComparison.toGrade})</span>
                ) : null}
              </div>
            </div>
          </div>

          {/* Cambios de Superficie */}
          <div className="rounded-xl border border-border bg-surface-2/60 p-3">
            <h5 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted">
              <Globe className="size-3.5" /> Variación en Superficie de Ataque
            </h5>
            <div className="mt-2 grid grid-cols-3 gap-2 text-center text-xs">
              <div className="rounded-lg bg-surface p-2 border border-border">
                <span className="text-muted">Subdominios nuevos</span>
                <p className="mt-0.5 text-sm font-semibold text-ink">
                  +{diff.surfaceChanges.newSubdomainsCount}
                </p>
              </div>
              <div className="rounded-lg bg-surface p-2 border border-border">
                <span className="text-muted">Puertos abiertos</span>
                <p className="mt-0.5 text-sm font-semibold text-amber-500">
                  +{diff.surfaceChanges.newOpenPortsCount}
                </p>
              </div>
              <div className="rounded-lg bg-surface p-2 border border-border">
                <span className="text-muted">Puertos cerrados</span>
                <p className="mt-0.5 text-sm font-semibold text-emerald-500">
                  -{diff.surfaceChanges.closedPortsCount}
                </p>
              </div>
            </div>
          </div>

          {/* Hallazgos Remediados vs Regresiones */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Remediados */}
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-3">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-600">
                  <CheckCircle2 className="size-4" /> Remediados con éxito ({diff.remediatedFindings.length})
                </span>
              </div>
              <div className="mt-2 max-h-48 space-y-2 overflow-y-auto pr-1">
                {diff.remediatedFindings.length === 0 ? (
                  <p className="text-xs text-muted">No se resolvieron hallazgos previos en este intervalo.</p>
                ) : (
                  diff.remediatedFindings.map((f, i) => (
                    <div
                      key={`${f.fingerprint}-${i}`}
                      className="rounded-lg border border-emerald-500/20 bg-surface p-2 text-xs"
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-medium text-ink line-clamp-1">{f.title}</span>
                        <SeverityBadge severity={f.severity} />
                      </div>
                      {f.location ? (
                        <span className="mt-0.5 block truncate text-[11px] text-muted">{f.location}</span>
                      ) : null}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Regresiones */}
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-3">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-xs font-semibold text-rose-600">
                  <AlertTriangle className="size-4" /> Nuevas Regresiones ({diff.newRegressions.length})
                </span>
              </div>
              <div className="mt-2 max-h-48 space-y-2 overflow-y-auto pr-1">
                {diff.newRegressions.length === 0 ? (
                  <p className="text-xs text-muted">No se detectaron nuevas brechas o regresiones.</p>
                ) : (
                  diff.newRegressions.map((f, i) => (
                    <div
                      key={`${f.fingerprint}-${i}`}
                      className="rounded-lg border border-rose-500/20 bg-surface p-2 text-xs"
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-medium text-ink line-clamp-1">{f.title}</span>
                        <SeverityBadge severity={f.severity} />
                      </div>
                      {f.location ? (
                        <span className="mt-0.5 block truncate text-[11px] text-muted">{f.location}</span>
                      ) : null}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Persistentes */}
          {diff.persistentFindings.length > 0 ? (
            <div className="flex items-center justify-between rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs text-muted">
              <span className="flex items-center gap-1.5">
                <Layers className="size-3.5" /> Hallazgos no resueltos aún persistentes:
              </span>
              <span className="font-semibold text-ink">{diff.persistentFindings.length} vulnerabilidad(es)</span>
            </div>
          ) : null}
        </div>
      )}
    </Modal>
  );
}
