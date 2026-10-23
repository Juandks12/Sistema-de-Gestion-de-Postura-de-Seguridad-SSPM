import {
  AlertCircle,
  Ban,
  CheckCircle2,
  GitCompare,
  Loader2,
  Sparkles,
} from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import type { DiagnosticBatchSummary, DiagnosticStageSummary } from '@/lib/types';
import { formatDateTime } from '@/lib/format';

interface Diagnostic360StepperProps {
  batch: DiagnosticBatchSummary;
  onCancel?: () => void;
  onOpenDiff?: () => void;
  isCancelling?: boolean;
}

const PROFILE_LABELS: Record<string, string> = {
  COMMERCE_360: 'Comercio Integral 360° (Superficie + Red + Web Profunda)',
  PERIMETER_FAST: 'Perímetro Rápido (Red, Puertos y Correo)',
  FULL_AUDIT: 'Auditoría Completa Exhaustiva',
};

export function Diagnostic360Stepper({
  batch,
  onCancel,
  onOpenDiff,
  isCancelling,
}: Diagnostic360StepperProps) {
  const isRunning = batch.status === 'RUNNING' || batch.status === 'PENDING';
  const isCompleted = batch.status === 'COMPLETED';
  const stageProgress = (batch.summary?.stageProgress ?? []) as DiagnosticStageSummary[];

  // Fallback de etapas si no vinieron en summary
  const stages: Array<{ stage: number; name: string; description: string; status: string; count: number }> =
    stageProgress.length > 0
      ? stageProgress.map((s) => ({
          stage: s.stage,
          name: s.name,
          description: s.description,
          status: s.status,
          count: s.scansCount,
        }))
      : [
          {
            stage: 1,
            name: 'Descubrimiento de Superficie',
            description: 'Enumeración DNS y detección de subdominios activos',
            status: batch.currentStage > 1 ? 'COMPLETED' : batch.currentStage === 1 ? batch.status : 'PENDING',
            count: 1,
          },
          {
            stage: 2,
            name: 'Perímetro, Puertos y Correo',
            description: 'Escaneo de puertos nmap y auditoría SPF/DKIM/DMARC/MTA-STS',
            status: batch.currentStage > 2 ? 'COMPLETED' : batch.currentStage === 2 ? batch.status : 'PENDING',
            count: 2,
          },
          {
            stage: 3,
            name: 'Web Profunda, E-Commerce y Secretos',
            description: 'Cabeceras, SSL, filtraciones JS, Magecart y checkout seguro',
            status: batch.currentStage === 3 && isCompleted ? 'COMPLETED' : batch.currentStage === 3 ? batch.status : 'PENDING',
            count: 3,
          },
        ];

  return (
    <Card className="border-accent/30 bg-surface shadow-sm">
      <CardHeader
        title={
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5">
              <Sparkles className="size-4 text-accent" />
              Diagnóstico Integral 360°
            </span>
            <span
              className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${
                isRunning
                  ? 'bg-sky-500/10 text-sky-500 animate-pulse'
                  : isCompleted
                    ? 'bg-emerald-500/10 text-emerald-500'
                    : batch.status === 'CANCELLED'
                      ? 'bg-amber-500/10 text-amber-500'
                      : 'bg-rose-500/10 text-rose-500'
              }`}
            >
              {isRunning ? 'En progreso...' : batch.status === 'COMPLETED' ? 'Completado' : batch.status}
            </span>
          </div>
        }
        subtitle={`${PROFILE_LABELS[batch.profile] ?? batch.profile} · iniciado ${formatDateTime(batch.createdAt)}`}
        action={
          <div className="flex items-center gap-2">
            {isRunning && onCancel ? (
              <Button
                variant="ghost"
                size="sm"
                className="text-critical hover:bg-critical/10"
                onClick={onCancel}
                loading={isCancelling}
                icon={<Ban className="size-4" />}
              >
                Cancelar
              </Button>
            ) : null}

            {onOpenDiff ? (
              <Button
                variant="secondary"
                size="sm"
                onClick={onOpenDiff}
                icon={<GitCompare className="size-4" />}
              >
                Comparar Postura (Diff)
              </Button>
            ) : null}
          </div>
        }
      />

      <CardBody>
        {/* Barra de progreso global */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs text-muted">
            <span>
              {isRunning
                ? `Ejecutando Etapa ${batch.currentStage} de ${batch.totalStages}`
                : isCompleted
                  ? 'Diagnóstico 360° finalizado con éxito'
                  : `Estado: ${batch.status}`}
            </span>
            <span className="font-semibold text-ink">{batch.progressPercentage}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-surface-2">
            <div
              className={`h-full transition-all duration-500 ${
                isCompleted
                  ? 'bg-emerald-500'
                  : batch.status === 'FAILED'
                    ? 'bg-rose-500'
                    : batch.status === 'CANCELLED'
                      ? 'bg-amber-500'
                      : 'bg-accent'
              }`}
              style={{ width: `${batch.progressPercentage}%` }}
            />
          </div>
        </div>

        {/* Stepper visual de etapas */}
        <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
          {stages.map((st) => {
            const isStageDone = st.status === 'COMPLETED';
            const isStageCurrent = st.status === 'RUNNING';
            const isStageFailed = st.status === 'FAILED';

            return (
              <div
                key={st.stage}
                className={`relative rounded-xl border p-3.5 transition-colors ${
                  isStageCurrent
                    ? 'border-accent bg-accent/5 ring-1 ring-accent/30'
                    : isStageDone
                      ? 'border-emerald-500/30 bg-emerald-500/5'
                      : isStageFailed
                        ? 'border-rose-500/30 bg-rose-500/5'
                        : 'border-border bg-surface-2/40'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div
                    className={`flex size-7 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
                      isStageDone
                        ? 'bg-emerald-500 text-white'
                        : isStageCurrent
                          ? 'bg-accent text-white animate-pulse'
                          : isStageFailed
                            ? 'bg-rose-500 text-white'
                            : 'bg-surface-2 text-muted'
                    }`}
                  >
                    {isStageDone ? (
                      <CheckCircle2 className="size-4" />
                    ) : isStageCurrent ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : isStageFailed ? (
                      <AlertCircle className="size-4" />
                    ) : (
                      st.stage
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <span className="block text-xs font-semibold uppercase tracking-wider text-muted">
                      Etapa {st.stage}
                    </span>
                    <h4 className="mt-0.5 truncate text-sm font-semibold text-ink">{st.name}</h4>
                    <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-ink-2">{st.description}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Resumen posterior a la finalización */}
        {isCompleted && batch.summary ? (
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3 text-xs">
            <div className="flex items-center gap-2 text-ink">
              <CheckCircle2 className="size-4 text-emerald-500 shrink-0" />
              <span>
                Auditoría encadenada completada ({batch.summary.totalScansEnqueued ?? 6} escaneos analizados en profundidad).
              </span>
            </div>
            {batch.summary.deltaScore !== undefined && batch.summary.deltaScore !== null ? (
              <div className="flex items-center gap-3">
                <span className="text-muted">
                  Score: <strong className="text-ink">{batch.summary.initialScore ?? 'N/A'}</strong> &rarr;{' '}
                  <strong className="text-ink">{batch.summary.finalScore ?? 'N/A'}</strong>
                </span>
                <span
                  className={`font-semibold ${
                    batch.summary.deltaScore >= 0 ? 'text-emerald-500' : 'text-rose-500'
                  }`}
                >
                  ({batch.summary.deltaScore >= 0 ? '+' : ''}{batch.summary.deltaScore} pts)
                </span>
              </div>
            ) : null}
          </div>
        ) : null}
      </CardBody>
    </Card>
  );
}
