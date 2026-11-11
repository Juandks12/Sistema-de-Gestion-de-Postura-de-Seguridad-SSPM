import { useEffect, useState } from 'react';
import {
  Activity,
  Bot,
  BrainCircuit,
  Coins,
  Cpu,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import { api } from '@/lib/api';
import type { LlmExecutionLogItem, LlmObservabilityStats } from '@/lib/types';

export function LlmObservabilityCard() {
  const [days, setDays] = useState<number>(30);
  const [stats, setStats] = useState<LlmObservabilityStats | null>(null);
  const [logs, setLogs] = useState<LlmExecutionLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'agents' | 'models' | 'logs'>('agents');

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, logsData] = await Promise.all([
        api<LlmObservabilityStats>(`/ai/observability/stats?days=${days}`),
        api<LlmExecutionLogItem[]>('/ai/observability/logs?limit=15'),
      ]);
      setStats(statsData);
      setLogs(logsData);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchData();
  }, [days]);

  return (
    <Card className="mt-6 border-indigo-500/20">
      <CardHeader
        title={
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <BrainCircuit className="h-5 w-5 text-indigo-400" />
              <div>
                <h3 className="font-semibold text-text">Observabilidad de LLMs y Seguridad de Agentes</h3>
                <p className="text-xs text-text-muted">
                  Telemetría en tiempo real: tokens consumidos, costo USD, latencias y neutralización de Prompt Injection.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <select
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                className="rounded-lg border border-border bg-surface-2 px-2.5 py-1 text-xs text-text focus:outline-none"
              >
                <option value={7}>Últimos 7 días</option>
                <option value={30}>Últimos 30 días</option>
                <option value={90}>Últimos 90 días</option>
              </select>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => void fetchData()}
                disabled={loading}
                className="gap-1 text-xs"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
                Actualizar
              </Button>
            </div>
          </div>
        }
      />
      <CardBody>
        {error && (
          <Alert kind="error" className="mb-4">
            Error al consultar observabilidad: {error}
          </Alert>
        )}

        {loading && !stats ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Skeleton className="h-20" />
            <Skeleton className="h-20" />
            <Skeleton className="h-20" />
            <Skeleton className="h-20" />
          </div>
        ) : (
          stats && (
            <>
              {/* Resumen de Métricas Clave */}
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                <div className="rounded-xl border border-border bg-surface-2/60 p-3.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Total Invocaciones</span>
                    <Activity className="h-4 w-4 text-primary" />
                  </div>
                  <div className="mt-1.5 text-xl font-bold text-text">{stats.totalCalls.toLocaleString()}</div>
                  <span className="text-[10px] text-text-muted">Llamadas a agentes y RAG</span>
                </div>

                <div className="rounded-xl border border-border bg-surface-2/60 p-3.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Tokens Consumidos</span>
                    <Cpu className="h-4 w-4 text-sky-400" />
                  </div>
                  <div className="mt-1.5 text-xl font-bold text-text">{stats.totalTokens.toLocaleString()}</div>
                  <span className="text-[10px] text-text-muted">In / Out agregados</span>
                </div>

                <div className="rounded-xl border border-border bg-surface-2/60 p-3.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Costo Estimado</span>
                    <Coins className="h-4 w-4 text-emerald-400" />
                  </div>
                  <div className="mt-1.5 text-xl font-bold text-emerald-400">${stats.totalCostUsd.toFixed(4)}</div>
                  <span className="text-[10px] text-text-muted">USD calculados por modelo</span>
                </div>

                <div className="rounded-xl border border-border bg-surface-2/60 p-3.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Latencia Promedio</span>
                    <Zap className="h-4 w-4 text-amber-400" />
                  </div>
                  <div className="mt-1.5 text-xl font-bold text-text">{stats.averageLatencyMs} ms</div>
                  <span className="text-[10px] text-text-muted">Tiempo total de inferencia</span>
                </div>

                <div className="rounded-xl border border-border bg-surface-2/60 p-3.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Ataques Neutralizados</span>
                    <ShieldCheck className="h-4 w-4 text-indigo-400" />
                  </div>
                  <div className="mt-1.5 flex items-baseline gap-2">
                    <div className="text-xl font-bold text-indigo-400">{stats.promptInjectionsBlocked}</div>
                    <span className="rounded bg-indigo-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-400 border border-indigo-500/30">
                      Shield Activo
                    </span>
                  </div>
                  <span className="text-[10px] text-text-muted">Prompt Injections bloqueados</span>
                </div>
              </div>

              {/* Pestañas de detalle */}
              <div className="mt-6 flex border-b border-border text-xs font-medium">
                <button
                  type="button"
                  onClick={() => setActiveTab('agents')}
                  className={`flex items-center gap-1.5 border-b-2 px-3.5 py-2 transition-colors ${
                    activeTab === 'agents'
                      ? 'border-indigo-400 text-indigo-400 font-semibold'
                      : 'border-transparent text-text-muted hover:text-text'
                  }`}
                >
                  <Bot className="h-3.5 w-3.5" />
                  Consumo por Agente
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('models')}
                  className={`flex items-center gap-1.5 border-b-2 px-3.5 py-2 transition-colors ${
                    activeTab === 'models'
                      ? 'border-indigo-400 text-indigo-400 font-semibold'
                      : 'border-transparent text-text-muted hover:text-text'
                  }`}
                >
                  <Cpu className="h-3.5 w-3.5" />
                  Desglose por Modelo
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('logs')}
                  className={`flex items-center gap-1.5 border-b-2 px-3.5 py-2 transition-colors ${
                    activeTab === 'logs'
                      ? 'border-indigo-400 text-indigo-400 font-semibold'
                      : 'border-transparent text-text-muted hover:text-text'
                  }`}
                >
                  <Activity className="h-3.5 w-3.5" />
                  Trazas Recientes ({logs.length})
                </button>
              </div>

              {/* Contenido de la pestaña */}
              <div className="mt-4">
                {activeTab === 'agents' && (
                  <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-4">
                    {Object.keys(stats.byAgent).length === 0 ? (
                      <div className="col-span-full py-6 text-center text-xs text-text-muted">
                        No hay ejecuciones registradas en el período seleccionado.
                      </div>
                    ) : (
                      Object.entries(stats.byAgent).map(([agentName, agentData]) => (
                        <div key={agentName} className="rounded-lg border border-border bg-surface-1 p-3">
                          <div className="font-medium text-text">{agentName}</div>
                          <div className="mt-2 space-y-1 text-xs text-text-muted">
                            <div className="flex justify-between">
                              <span>Invocaciones:</span>
                              <span className="font-semibold text-text">{agentData.calls}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Tokens:</span>
                              <span className="font-semibold text-text">{agentData.tokens.toLocaleString()}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Costo USD:</span>
                              <span className="font-semibold text-emerald-400">${agentData.costUsd.toFixed(4)}</span>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {activeTab === 'models' && (
                  <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-3">
                    {Object.keys(stats.byModel).length === 0 ? (
                      <div className="col-span-full py-6 text-center text-xs text-text-muted">
                        No hay modelos registrados aún.
                      </div>
                    ) : (
                      Object.entries(stats.byModel).map(([modelName, modelData]) => (
                        <div key={modelName} className="rounded-lg border border-border bg-surface-1 p-3">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-xs font-semibold text-primary">{modelName}</span>
                            <span className="rounded border border-border px-1.5 py-0.5 text-[10px] text-text-muted">
                              {modelData.calls} llamadas
                            </span>
                          </div>
                          <div className="mt-2 flex justify-between text-xs text-text-muted">
                            <span>Gasto acumulado:</span>
                            <span className="font-semibold text-emerald-400">${modelData.costUsd.toFixed(4)}</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {activeTab === 'logs' && (
                  <div className="overflow-x-auto">
                    <Table>
                      <thead>
                        <tr>
                          <Th>Fecha</Th>
                          <Th>Agente / Servicio</Th>
                          <Th>Modelo</Th>
                          <Th>Tokens</Th>
                          <Th>Latencia</Th>
                          <Th>Estado & Guardrails</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {logs.length === 0 ? (
                          <tr>
                            <Td colSpan={6} className="text-center text-xs text-text-muted">
                              No hay trazas de IA recientes registradas.
                            </Td>
                          </tr>
                        ) : (
                          logs.map((log) => (
                            <tr key={log.id} className="border-t border-border hover:bg-surface-2/40">
                              <Td className="text-[11px] text-text-muted whitespace-nowrap">
                                {new Date(log.createdAt).toLocaleTimeString([], {
                                  hour: '2-digit',
                                  minute: '2-digit',
                                  second: '2-digit',
                                })}
                              </Td>
                              <Td className="font-medium text-xs text-text">{log.agentOrService}</Td>
                              <Td className="font-mono text-[11px] text-text-muted">{log.model}</Td>
                              <Td className="text-xs text-text">{log.totalTokens.toLocaleString()}</Td>
                              <Td className="text-xs text-text">{log.latencyMs} ms</Td>
                              <Td>
                                {log.status === 'BLOCKED_INJECTION' ? (
                                  <span className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-400 border border-amber-500/30">
                                    <ShieldAlert className="h-3 w-3" />
                                    Injection Bloqueada
                                  </span>
                                ) : log.status === 'FALLBACK_HEURISTIC' ? (
                                  <span className="rounded bg-surface-2 px-2 py-0.5 text-[10px] text-ink-2 font-medium">
                                    Fallback Heurístico
                                  </span>
                                ) : (
                                  <span className="rounded bg-good/12 px-2 py-0.5 text-[10px] text-good-text font-medium">
                                    Éxito
                                  </span>
                                )}
                              </Td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </Table>
                  </div>
                )}
              </div>
            </>
          )
        )}
      </CardBody>
    </Card>
  );
}

