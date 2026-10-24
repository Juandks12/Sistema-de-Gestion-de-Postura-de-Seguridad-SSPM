import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CreditCard,
  Database,
  ExternalLink,
  GitFork,
  Globe2,
  KeyRound,
  MailWarning,
  ServerCrash,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import { useState } from 'react';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Skeleton } from '@/components/ui/Spinner';
import { useAttackPaths } from '@/hooks/queries';
import { cn } from '@/lib/cn';
import type { AttackPathCategory, AttackPathSeverity } from '@/lib/types';

interface AttackPathsCardProps {
  assetId?: string;
  onSelectQuickWins?: () => void;
  onFilterRule?: (ruleId: string) => void;
}

const CATEGORY_ICON: Record<AttackPathCategory, typeof CreditCard> = {
  PAYMENT_FRAUD: CreditCard,
  STORE_TAKEOVER: KeyRound,
  BRAND_IMPERSONATION: MailWarning,
  DATA_EXFILTRATION: Database,
  INFRASTRUCTURE_COMPROMISE: ServerCrash,
  SUBDOMAIN_TAKEOVER: Globe2,
};

const SEVERITY_BADGE: Record<AttackPathSeverity, string> = {
  CRITICAL: 'border-rose-500/30 bg-rose-500/10 text-rose-500 dark:text-rose-400',
  HIGH: 'border-amber-500/30 bg-amber-500/10 text-amber-500 dark:text-amber-400',
  MEDIUM: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-500 dark:text-yellow-400',
};

const EFFORT_BADGE = {
  QUICK_WIN: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20',
  MODERATE: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20',
  STRUCTURAL: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20',
};

export function AttackPathsCard({ assetId, onSelectQuickWins, onFilterRule }: AttackPathsCardProps) {
  const { data: attackPaths, isLoading, isError } = useAttackPaths(assetId);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (isLoading) {
    return (
      <Card className="border-border bg-surface p-5">
        <div className="flex items-center gap-3">
          <Skeleton className="size-8 rounded-lg" />
          <div className="space-y-2">
            <Skeleton className="h-4 w-64" />
            <Skeleton className="h-3 w-40" />
          </div>
        </div>
      </Card>
    );
  }

  if (isError || !attackPaths || attackPaths.length === 0) {
    return null;
  }

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const totalQuickWins = attackPaths.reduce((acc, p) => acc + p.quickWinsAvailable, 0);

  return (
    <Card className="overflow-hidden border-rose-500/25 bg-surface shadow-sm">
      <CardHeader
        title={
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <span className="flex size-7 items-center justify-center rounded-lg bg-rose-500/15 text-rose-500">
                <GitFork className="size-4" />
              </span>
              <div>
                <span className="text-sm font-semibold text-ink">
                  Rutas de Ataque y Escenarios de Riesgo Compuesto (Attack Paths)
                </span>
                <p className="text-xs text-muted">
                  Correlación automática de vulnerabilidades que un atacante puede encadenar contra tu comercio.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-0.5 text-xs font-semibold text-rose-500">
                <AlertTriangle className="size-3" />
                {attackPaths.length} {attackPaths.length === 1 ? 'Ruta activa' : 'Rutas activas'}
              </span>

              {totalQuickWins > 0 && onSelectQuickWins && (
                <button
                  type="button"
                  onClick={onSelectQuickWins}
                  className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-0.5 text-xs font-medium text-emerald-600 transition hover:bg-emerald-500/20 dark:text-emerald-400"
                >
                  <Zap className="size-3 text-emerald-500 fill-emerald-500" />
                  {totalQuickWins} Quick Wins 24h
                </button>
              )}
            </div>
          </div>
        }
      />

      <CardBody className="divide-y divide-border p-0">
        {attackPaths.map((path) => {
          const Icon = CATEGORY_ICON[path.category] ?? ShieldAlert;
          const isExpanded = expandedId === path.id;

          return (
            <div key={path.id} className="transition-colors hover:bg-surface-2/30">
              {/* Header row */}
              <div
                role="button"
                tabIndex={0}
                onClick={() => toggleExpand(path.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleExpand(path.id);
                  }
                }}
                className="flex cursor-pointer items-start justify-between gap-4 p-4 text-left sm:items-center"
              >
                <div className="flex items-start gap-3 sm:items-center">
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-surface-2 text-ink">
                    <Icon className="size-4.5" />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-ink">{path.title}</span>
                      <span
                        className={cn(
                          'rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider',
                          SEVERITY_BADGE[path.severity],
                        )}
                      >
                        {path.severity}
                      </span>
                      {path.quickWinsAvailable > 0 && (
                        <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
                          <Zap className="size-3 fill-emerald-500 text-emerald-500" />
                          {path.quickWinsAvailable} Quick Win{path.quickWinsAvailable > 1 ? 's' : ''}
                        </span>
                      )}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
                      {path.assetValue && (
                        <span>
                          Activo objetivo:{' '}
                          <strong className="font-medium text-ink-2">
                            {path.assetName ? `${path.assetName} (${path.assetValue})` : path.assetValue}
                          </strong>
                        </span>
                      )}
                      <span>
                        {path.activeFindings.length} hallazgo{path.activeFindings.length > 1 ? 's' : ''} involucrado
                        {path.activeFindings.length > 1 ? 's' : ''}
                      </span>
                      <span>·</span>
                      <span className="text-rose-500 font-medium">Impacto: {path.estimatedImpact.split('—')[0]}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <Button variant="ghost" size="sm" className="size-8 p-0">
                    {isExpanded ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
                  </Button>
                </div>
              </div>

              {/* Collapsible Details */}
              {isExpanded && (
                <div className="bg-surface-2/20 px-4 pb-5 pt-2 border-t border-border">
                  {/* Narrative & Business Risk */}
                  <div className="mb-4 grid gap-3 rounded-lg border border-border bg-surface p-3.5 sm:grid-cols-2">
                    <div>
                      <span className="text-[11px] font-bold uppercase tracking-wider text-muted">
                        Narrativa del Vector de Ataque
                      </span>
                      <p className="mt-1 text-xs leading-relaxed text-ink-2">{path.narrative}</p>
                    </div>
                    <div>
                      <span className="text-[11px] font-bold uppercase tracking-wider text-rose-500">
                        Riesgo e Impacto para el Comercio
                      </span>
                      <p className="mt-1 text-xs leading-relaxed text-ink-2">{path.businessRisk}</p>
                      <p className="mt-2 text-[11px] font-medium text-muted">
                        Estimación: <span className="text-ink">{path.estimatedImpact}</span>
                      </p>
                    </div>
                  </div>

                  {/* Kill Chain Visual Timeline */}
                  <div className="mb-4">
                    <span className="text-xs font-semibold uppercase tracking-wider text-muted">
                      Cadena de Ataque Encadenada (Kill Chain)
                    </span>
                    <div className="mt-2.5 space-y-3">
                      {path.killChainSteps.map((step, idx) => (
                        <div key={step.order} className="relative flex items-start gap-3">
                          {idx < path.killChainSteps.length - 1 && (
                            <span
                              className="absolute left-[13px] top-6 -bottom-3 w-0.5 bg-border"
                              aria-hidden="true"
                            />
                          )}
                          <div
                            className={cn(
                              'relative z-10 flex size-7 shrink-0 items-center justify-center rounded-full text-xs font-bold',
                              step.matched
                                ? 'bg-rose-500 text-white shadow-xs'
                                : 'border border-border bg-surface-2 text-muted',
                            )}
                          >
                            {step.matched ? <CheckCircle2 className="size-4" /> : step.order}
                          </div>
                          <div className="flex-1 pb-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-xs font-semibold text-ink">{step.title}</span>
                              <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] font-medium text-muted">
                                {step.phase}
                              </span>
                              {step.matched && (
                                <span className="rounded border border-rose-500/20 bg-rose-500/10 px-1.5 py-0.5 text-[10px] font-bold text-rose-500">
                                  Activo en el activo
                                </span>
                              )}
                            </div>
                            <p className="mt-0.5 text-xs text-muted leading-relaxed">{step.description}</p>
                            {step.findingTitle && (
                              <div className="mt-1 flex items-center gap-1.5 text-[11px] text-ink-2 font-mono">
                                <span>Hallazgo:</span>
                                <span className="font-semibold">{step.findingTitle}</span>
                                {step.location && <span className="text-muted">({step.location})</span>}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Correlated Active Findings */}
                  <div className="mb-4">
                    <span className="text-xs font-semibold uppercase tracking-wider text-muted">
                      Hallazgos Abiertos Asociados ({path.activeFindings.length})
                    </span>
                    <div className="mt-2 grid gap-2 sm:grid-cols-2">
                      {path.activeFindings.map((f) => (
                        <div
                          key={f.id}
                          className="flex items-center justify-between gap-2 rounded-lg border border-border bg-surface p-2.5 text-xs"
                        >
                          <div className="min-w-0 flex-1">
                            <p className="truncate font-medium text-ink">{f.title}</p>
                            <p className="truncate text-[11px] text-muted">{f.location || f.ruleId}</p>
                          </div>
                          <div className="flex shrink-0 items-center gap-1.5">
                            <span
                              className={cn(
                                'rounded px-1.5 py-0.5 text-[10px] font-bold',
                                EFFORT_BADGE[f.effort],
                              )}
                            >
                              {f.effort === 'QUICK_WIN'
                                ? `Quick Win (${f.estimatedMinutes}m)`
                                : f.effort === 'MODERATE'
                                  ? `Moderado (${f.estimatedMinutes}m)`
                                  : 'Estructural'}
                            </span>
                            {onFilterRule && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => onFilterRule(f.ruleId)}
                                className="size-6 p-0 text-muted hover:text-ink"
                                title="Filtrar por esta regla"
                              >
                                <ExternalLink className="size-3" />
                              </Button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Remediation Priorities */}
                  <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
                    <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400">
                      Acciones Recomendadas para Desactivar esta Ruta de Ataque:
                    </span>
                    <ul className="mt-1.5 space-y-1">
                      {path.recommendedActions.map((action, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-ink-2">
                          <CheckCircle2 className="size-3.5 shrink-0 text-emerald-500 mt-0.5" />
                          <span>{action}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </CardBody>
    </Card>
  );
}
