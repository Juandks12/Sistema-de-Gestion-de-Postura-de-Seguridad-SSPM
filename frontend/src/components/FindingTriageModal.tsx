import {
  AlertOctagon,
  Bot,
  Check,
  CheckCircle2,
  Cpu,
  HelpCircle,
  RefreshCw,
  ShieldAlert,
  Sparkles,
} from 'lucide-react';
import { useState } from 'react';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Modal } from '@/components/ui/Modal';
import { Skeleton } from '@/components/ui/Spinner';
import { useFindingTriage, useRefreshFindingTriage, useRetestFinding, useReviewFinding } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import type { Finding, TriageContextFactor, TriageVerdict } from '@/lib/types';

interface FindingTriageModalProps {
  finding: Finding | null;
  canEdit: boolean;
  onClose: () => void;
}

const VERDICT_CONFIG: Record<
  TriageVerdict,
  { label: string; badgeClass: string; icon: typeof CheckCircle2 }
> = {
  PROBABLE_FALSE_POSITIVE: {
    label: 'Probable Falso Positivo',
    badgeClass: 'border-good/30 bg-good/10 text-good-text',
    icon: CheckCircle2,
  },
  NEEDS_VERIFICATION: {
    label: 'Requiere Verificación Manual',
    badgeClass: 'border-warning/30 bg-warning/15 text-[#8a5b00] dark:text-warning',
    icon: HelpCircle,
  },
  CONFIRMED_TRUE_POSITIVE: {
    label: 'Riesgo Confirmado (True Positive)',
    badgeClass: 'border-critical/30 bg-critical/10 text-critical',
    icon: ShieldAlert,
  },
};

export function FindingTriageModal({ finding, canEdit, onClose }: FindingTriageModalProps) {
  const findingId = finding?.id ?? null;
  const triage = useFindingTriage(findingId, Boolean(findingId));
  const refreshMutation = useRefreshFindingTriage();
  const reviewMutation = useReviewFinding();
  const retestMutation = useRetestFinding();

  const [customNote, setCustomNote] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [retestResult, setRetestResult] = useState<{ stillReproducible: boolean; message: string } | null>(null);

  const data = triage.data;
  const note = customNote ?? (data?.suggestedNote ?? '');

  const handleRefresh = async () => {
    if (!findingId) return;
    setActionError(null);
    setActionSuccess(null);
    try {
      await refreshMutation.mutateAsync(findingId);
      setCustomNote(null);
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Error al actualizar el análisis.');
    }
  };

  const handleApplyReview = async (status: 'FALSE_POSITIVE' | 'ACCEPTED') => {
    if (!findingId) return;
    setActionError(null);
    setActionSuccess(null);
    try {
      await reviewMutation.mutateAsync({
        id: findingId,
        status,
        note: note.trim() || undefined,
      });
      setActionSuccess(
        status === 'FALSE_POSITIVE'
          ? 'Hallazgo descartado como falso positivo con éxito.'
          : 'Riesgo aceptado correctamente.',
      );
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Error al guardar la revisión.');
    }
  };

  const handleRetest = async () => {
    if (!findingId) return;
    setActionError(null);
    setActionSuccess(null);
    setRetestResult(null);
    try {
      const res = await retestMutation.mutateAsync(findingId);
      setRetestResult({
        stillReproducible: res.stillReproducible,
        message: res.message,
      });
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Error al ejecutar la sonda de verificación.');
    }
  };

  if (!finding) return null;

  const verdictMeta = data ? VERDICT_CONFIG[data.verdict] : null;
  const VerdictIcon = verdictMeta?.icon ?? AlertOctagon;

  return (
    <Modal
      open={Boolean(finding)}
      onClose={onClose}
      title="Triage Asistido de Hallazgo"
      size="xl"
      footer={
        <div className="flex w-full items-center justify-between gap-3">
          <Button
            size="sm"
            variant="secondary"
            icon={<RefreshCw className={cn('size-3.5', refreshMutation.isPending && 'animate-spin')} />}
            loading={refreshMutation.isPending}
            onClick={handleRefresh}
            title="Recalcular análisis forzando consulta al motor y LLM"
          >
            Actualizar diagnóstico
          </Button>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={onClose}>
              Cerrar
            </Button>
          </div>
        </div>
      }
    >
      <div className="space-y-4">
        {/* Encabezado contextual del hallazgo */}
        <div className="rounded-xl border border-border bg-surface-2/40 p-3.5 text-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-medium text-ink">{finding.title}</h3>
            <span className="text-xs text-muted font-mono">{finding.ruleId}</span>
          </div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2">
            <div>
              <span className="text-muted">Activo: </span>
              <span className="font-medium text-ink">{finding.asset.name ?? finding.asset.value}</span>
            </div>
            <div>
              <span className="text-muted">Ubicación: </span>
              <span className="font-mono">{finding.location}</span>
            </div>
          </div>
        </div>

        {/* Estado de carga */}
        {triage.isPending ? (
          <div className="space-y-3 py-6 text-center">
            <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-accent/10 text-accent-strong">
              <Sparkles className="size-6 animate-pulse" />
            </div>
            <p className="text-sm font-medium text-ink">Analizando contexto y telemetría del hallazgo...</p>
            <p className="text-xs text-muted">Evaluando tipo de activo, cabeceras, rutas de servicio y falsos positivos comunes.</p>
            <div className="mx-auto max-w-md space-y-2 pt-2">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-5/6" />
            </div>
          </div>
        ) : null}

        {/* Estado de error */}
        {triage.isError ? (
          <Alert kind="error" className="my-2">
            No se pudo obtener el diagnóstico asistido:{' '}
            {triage.error instanceof ApiError ? triage.error.message : 'Error de comunicación con el servicio de triage.'}
          </Alert>
        ) : null}

        {/* Diagnóstico completado */}
        {data ? (
          <>
            {/* Banner del Veredicto y Confianza */}
            <div className={cn('rounded-xl border p-4 transition-colors', verdictMeta?.badgeClass)}>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <VerdictIcon className="size-5 shrink-0" />
                  <div>
                    <span className="text-xs font-semibold uppercase tracking-wider opacity-80">
                      Diagnóstico de Triage
                    </span>
                    <h4 className="text-base font-bold">{verdictMeta?.label}</h4>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 text-xs">
                  {/* Badge de Proveedor */}
                  <span
                    className={cn(
                      'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-medium',
                      data.provider === 'ai'
                        ? 'bg-accent/20 text-accent-strong'
                        : 'bg-surface-2 text-ink-2 border border-border',
                    )}
                  >
                    {data.provider === 'ai' ? <Bot className="size-3.5" /> : <Cpu className="size-3.5" />}
                    {data.provider === 'ai' ? 'Síntesis IA (DeepSeek)' : 'Motor Heurístico Experto'}
                  </span>

                  {/* Confianza */}
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-current/20 px-2.5 py-1 font-medium">
                    <span>Confianza:</span>
                    <span className="font-bold">{data.confidenceScore}%</span>
                  </span>
                </div>
              </div>

              {/* Barra de Confianza Visual */}
              <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-current/15">
                <div
                  className="h-full bg-current transition-all duration-500"
                  style={{ width: `${Math.max(5, data.confidenceScore)}%` }}
                />
              </div>

              {/* Resumen */}
              <p className="mt-3 text-sm font-normal text-ink leading-relaxed">
                {data.summary}
              </p>
            </div>

            {/* Razonamiento contextual */}
            {data.reasoning && data.reasoning.length > 0 ? (
              <div className="rounded-xl border border-border bg-surface p-4">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">
                  Argumentación Técnica y Justificación
                </h4>
                <ul className="mt-2 space-y-1.5 text-sm text-ink-2">
                  {data.reasoning.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="mt-1 size-1.5 shrink-0 rounded-full bg-accent" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {/* Factores Contextuales Evaluados */}
            {data.contextFactors && data.contextFactors.length > 0 ? (
              <div className="rounded-xl border border-border bg-surface p-4">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">
                  Factores de Contexto Evaluados ({data.contextFactors.length})
                </h4>
                <div className="mt-2.5 divide-y divide-line text-xs">
                  {data.contextFactors.map((factor: TriageContextFactor, idx: number) => (
                    <div key={idx} className="py-2 first:pt-0 last:pb-0 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5">
                      <div>
                        <span className="font-medium text-ink">{factor.factor}</span>
                        <p className="text-muted mt-0.5">{factor.detail}</p>
                      </div>
                      <span
                        className={cn(
                          'inline-flex shrink-0 items-center rounded-md px-2 py-0.5 font-medium',
                          factor.impact === 'INCREASES_FP_PROBABILITY' && 'bg-good/15 text-good-text',
                          factor.impact === 'DECREASES_FP_PROBABILITY' && 'bg-critical/15 text-critical',
                          factor.impact === 'NEUTRAL' && 'bg-surface-2 text-ink-2',
                        )}
                      >
                        {factor.impact === 'INCREASES_FP_PROBABILITY' && '+ Probable FP'}
                        {factor.impact === 'DECREASES_FP_PROBABILITY' && '+ Riesgo Real'}
                        {factor.impact === 'NEUTRAL' && 'Neutro'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {/* Mensajes de feedback */}
            {actionSuccess ? (
              <Alert kind="success" className="my-2">
                {actionSuccess}
              </Alert>
            ) : null}
            {actionError ? (
              <Alert kind="error" className="my-2">
                {actionError}
              </Alert>
            ) : null}
            {retestResult ? (
              <Alert kind={retestResult.stillReproducible ? 'error' : 'success'} className="my-2">
                {retestResult.message}
              </Alert>
            ) : null}

            {/* Acciones del Analista */}
            {canEdit ? (
              <div className="rounded-xl border border-border bg-surface-2/30 p-4">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-muted">
                    Acción Recomendada & Resolución
                  </h4>
                  <span className="text-xs font-medium text-ink">
                    Recomendación: <span className="text-accent-strong uppercase font-bold">{data.recommendedAction}</span>
                  </span>
                </div>

                {/* Textarea para nota técnica sugerida */}
                <div className="mt-3">
                  <label htmlFor="triage-note" className="block text-xs font-medium text-ink-2 mb-1">
                    Nota técnica / Justificación contextual para auditoría:
                  </label>
                  <textarea
                    id="triage-note"
                    rows={3}
                    className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-xs text-ink placeholder:text-muted focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
                    value={note}
                    onChange={(e) => setCustomNote(e.target.value)}
                    placeholder="Justificación para marcar falso positivo o aceptar riesgo..."
                  />
                </div>

                {/* Botones de acción directa */}
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  {data.recommendedAction === 'MARK_FALSE_POSITIVE' || data.verdict === 'PROBABLE_FALSE_POSITIVE' ? (
                    <Button
                      variant="primary"
                      icon={<Check className="size-4" />}
                      loading={reviewMutation.isPending}
                      onClick={() => handleApplyReview('FALSE_POSITIVE')}
                    >
                      Aplicar: Descartar como Falso Positivo
                    </Button>
                  ) : null}

                  {data.recommendedAction === 'ACCEPT_RISK' ? (
                    <Button
                      variant="primary"
                      icon={<Check className="size-4" />}
                      loading={reviewMutation.isPending}
                      onClick={() => handleApplyReview('ACCEPTED')}
                    >
                      Aplicar: Aceptar Riesgo
                    </Button>
                  ) : null}

                  {data.recommendedAction === 'RETEST' ? (
                    <Button
                      variant="primary"
                      icon={<RefreshCw className="size-4" />}
                      loading={retestMutation.isPending}
                      onClick={handleRetest}
                    >
                      Aplicar: Re-verificar con Sonda
                    </Button>
                  ) : null}

                  {/* Acciones alternativas secundarias */}
                  {data.recommendedAction !== 'MARK_FALSE_POSITIVE' && data.verdict !== 'PROBABLE_FALSE_POSITIVE' && (
                    <Button
                      size="sm"
                      variant="secondary"
                      loading={reviewMutation.isPending}
                      onClick={() => handleApplyReview('FALSE_POSITIVE')}
                    >
                      Marcar como Falso Positivo
                    </Button>
                  )}

                  {data.recommendedAction !== 'ACCEPT_RISK' && (
                    <Button
                      size="sm"
                      variant="secondary"
                      loading={reviewMutation.isPending}
                      onClick={() => handleApplyReview('ACCEPTED')}
                    >
                      Aceptar Riesgo
                    </Button>
                  )}

                  {data.recommendedAction !== 'RETEST' && (
                    <Button
                      size="sm"
                      variant="secondary"
                      icon={<RefreshCw className="size-3.5" />}
                      loading={retestMutation.isPending}
                      onClick={handleRetest}
                    >
                      Re-verificar
                    </Button>
                  )}
                </div>
              </div>
            ) : null}
          </>
        ) : null}
      </div>
    </Modal>
  );
}
