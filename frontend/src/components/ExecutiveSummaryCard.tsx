import {
  Activity,
  AlertTriangle,
  Building2,
  DollarSign,
  Layers,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Skeleton } from '@/components/ui/Spinner';
import { useExecutiveSummary, useRefreshExecutiveSummary } from '@/hooks/queries';
import type { BusinessImpact } from '@/lib/types';

const IMPACT_ICONS: Record<BusinessImpact['area'], typeof Activity> = {
  Operativa: Activity,
  Financiera: DollarSign,
  'Regulatoria/Legal': Building2,
  Reputacional: ShieldCheck,
};

const RISK_BADGE_CLASS: Record<string, string> = {
  CRÍTICO: 'border-rose-500/30 bg-rose-500/10 text-rose-400',
  ALTO: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
  MODERADO: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400',
  BAJO: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400',
};

const SEVERITY_PILL_CLASS: Record<string, string> = {
  CRÍTICO: 'bg-rose-500/15 text-rose-400',
  ALTO: 'bg-amber-500/15 text-amber-400',
  MEDIO: 'bg-yellow-500/15 text-yellow-400',
  BAJO: 'bg-emerald-500/15 text-emerald-400',
};

export function ExecutiveSummaryCard({ assetId, title }: { assetId?: string; title?: string }) {
  const q = useExecutiveSummary(assetId);
  const refresh = useRefreshExecutiveSummary();

  const handleRefresh = async () => {
    try {
      await refresh.mutateAsync(assetId);
    } catch {
      // Ignorar error controlado
    }
  };

  const summary = q.data;

  return (
    <Card className="overflow-hidden border-accent/25 bg-surface shadow-sm">
      <CardHeader
        title={
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-lg bg-accent/15 text-accent">
              <Sparkles className="size-4" />
            </span>
            <span>{title ?? 'Diagnóstico Ejecutivo de Postura de Seguridad'}</span>
          </div>
        }
        subtitle="Síntesis estratégica orientada a la toma de decisiones y evaluación de impacto en el negocio."
        action={
          <div className="flex items-center gap-2">
            {summary ? (
              <span className="hidden items-center gap-1 rounded-md bg-surface-2 px-2 py-0.5 text-[11px] font-medium text-muted sm:inline-flex">
                <Sparkles className="size-3 text-accent" />
                {summary.provider === 'ai' ? 'Síntesis IA' : 'Motor Experto'}
              </span>
            ) : null}
            <Button
              size="sm"
              variant="secondary"
              icon={<RefreshCw className="size-3.5" />}
              loading={refresh.isPending || q.isFetching}
              onClick={handleRefresh}
              title="Regenerar análisis de riesgo ejecutivo"
            >
              Actualizar
            </Button>
          </div>
        }
      />
      <CardBody>
        {q.isPending ? (
          <div className="space-y-3.5">
            <Skeleton className="h-14 w-full rounded-xl" />
            <Skeleton className="h-20 w-full rounded-xl" />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {[0, 1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-28 rounded-lg" />
              ))}
            </div>
          </div>
        ) : q.isError || !summary ? (
          <div className="rounded-lg border border-dashed border-border p-6 text-center">
            <AlertTriangle className="mx-auto size-7 text-muted" />
            <p className="mt-2 text-sm text-ink-2">No se pudo cargar el resumen ejecutivo en este momento.</p>
            <Button size="sm" variant="secondary" className="mt-3" onClick={() => q.refetch()}>
              Reintentar
            </Button>
          </div>
        ) : (
          <div className="space-y-5">
            {/* Titular Diagnóstico y Badge de Nivel de Riesgo */}
            <div className="flex flex-col gap-3 rounded-xl border border-accent/20 bg-accent/5 p-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold ${
                      RISK_BADGE_CLASS[summary.riskLevel] ?? 'border-border bg-surface-2 text-ink-2'
                    }`}
                  >
                    <ShieldAlert className="size-3" />
                    Riesgo {summary.riskLevel}
                  </span>
                  <span className="text-xs text-muted">· {summary.scoreOverview.trendLabel}</span>
                </div>
                <h3 className="mt-1.5 font-medium text-sm text-ink leading-snug">{summary.headline}</h3>
              </div>
            </div>

            {/* Párrafo de Visión Ejecutiva */}
            <div className="rounded-lg bg-surface-2/40 p-4 text-xs text-ink-2 leading-relaxed sm:text-sm">
              <p>{summary.executiveOverview}</p>
            </div>

            {/* Cuadrícula de Impactos en el Negocio */}
            <div>
              <h4 className="mb-2.5 font-semibold text-xs text-muted tracking-wider uppercase">
                Evaluación de Impacto en el Negocio
              </h4>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {summary.businessImpacts.map((impact) => {
                  const Icon = IMPACT_ICONS[impact.area] ?? Activity;
                  return (
                    <div
                      key={impact.area}
                      className="flex flex-col justify-between rounded-xl border border-border bg-surface-2/30 p-3.5 transition-colors hover:border-line"
                    >
                      <div>
                        <div className="flex items-center justify-between gap-1.5">
                          <span className="flex size-7 items-center justify-center rounded-lg bg-surface-2 text-ink">
                            <Icon className="size-3.5" />
                          </span>
                          <span
                            className={`rounded-full px-2 py-0.5 font-semibold text-[10px] tracking-wide uppercase ${
                              SEVERITY_PILL_CLASS[impact.severity] ?? 'bg-surface-2 text-muted'
                            }`}
                          >
                            {impact.severity}
                          </span>
                        </div>
                        <h5 className="mt-2 font-medium text-xs text-ink">{impact.area}</h5>
                        <p className="mt-1 text-[11px] text-ink-2 leading-relaxed">{impact.description}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Top 3 Acciones Prioritarias Estratégicas */}
            {summary.topPriorities.length > 0 ? (
              <div>
                <h4 className="mb-2.5 font-semibold text-xs text-muted tracking-wider uppercase">
                  Top Acciones Prioritarias Recomendadas
                </h4>
                <div className="space-y-2.5">
                  {summary.topPriorities.map((priority) => (
                    <div
                      key={priority.order}
                      className="flex items-start gap-3 rounded-xl border border-border bg-surface-2/20 p-3.5"
                    >
                      <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-accent/15 font-semibold text-xs text-accent">
                        {priority.order}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center justify-between gap-1">
                          <h5 className="font-medium text-xs text-ink sm:text-sm">{priority.title}</h5>
                          <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-muted">
                            {priority.affectedTarget}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-ink">{priority.action}</p>
                        <p className="mt-1 text-[11px] text-muted italic">
                          Por qué priorizarlo: {priority.businessJustification}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {/* Nota de Deuda Técnica */}
            {summary.technicalDebtSummary ? (
              <div className="flex items-start gap-2.5 rounded-lg border border-border bg-surface-2/30 p-3 text-xs text-ink-2">
                <Layers className="size-4 shrink-0 text-muted mt-0.5" />
                <p className="leading-relaxed">{summary.technicalDebtSummary}</p>
              </div>
            ) : null}
          </div>
        )}
      </CardBody>
    </Card>
  );
}
