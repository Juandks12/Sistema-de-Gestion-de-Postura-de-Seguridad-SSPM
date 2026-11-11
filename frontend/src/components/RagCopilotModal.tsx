import { useState, useEffect } from 'react';
import {
  Sparkles,
  Copy,
  Check,
  ShieldCheck,
  Terminal,
  Code2,
  BookOpen,
  RefreshCw,
  ExternalLink,
  Cpu,
} from 'lucide-react';
import { Modal } from '@/components/ui/Modal';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { SeverityBadge } from '@/components/ui/Badge';
import { Skeleton } from '@/components/ui/Spinner';
import { api } from '@/lib/api';
import type { Finding, GroundedRemediationPlaybook } from '@/lib/types';

interface RagCopilotModalProps {
  finding: Finding;
  onClose: () => void;
}

export function RagCopilotModal({ finding, onClose }: RagCopilotModalProps) {
  const [loading, setLoading] = useState(true);
  const [playbook, setPlaybook] = useState<GroundedRemediationPlaybook | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedSnippetIdx, setCopiedSnippetIdx] = useState<number | null>(null);
  const [copiedCommand, setCopiedCommand] = useState(false);

  const fetchPlaybook = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api<GroundedRemediationPlaybook>(
        `/ai/rag/remediation-advice/${finding.id}`,
        {
          method: 'POST',
          json: {},
        },
      );
      setPlaybook(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(`No se pudo generar el playbook RAG: ${msg}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPlaybook();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finding.id]);

  const copyToClipboard = (text: string, type: 'snippet' | 'command', idx?: number) => {
    navigator.clipboard.writeText(text);
    if (type === 'snippet' && idx !== undefined) {
      setCopiedSnippetIdx(idx);
      setTimeout(() => setCopiedSnippetIdx(null), 2000);
    } else {
      setCopiedCommand(true);
      setTimeout(() => setCopiedCommand(false), 2000);
    }
  };

  return (
    <Modal
      open={true}
      onClose={onClose}
      title="SecAudit Copilot — Asistente Grounded RAG"
      size="xl"
    >
      <div className="space-y-6">
        {/* Subheader banner */}
        <div className="flex items-center justify-between pb-3 border-b border-border text-xs">
          <div className="flex items-center gap-2">
            <span className="p-1 rounded bg-primary-500/10 text-primary-400">
              <Sparkles className="w-4 h-4" />
            </span>
            <span className="text-text-muted">
              Remediación técnica libre de alucinaciones indexada contra CISA KEV, GRC e IaC
            </span>
          </div>
          <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1 font-mono text-[11px]">
            <Cpu className="w-3 h-3" /> pgvector HNSW
          </span>
        </div>

        {/* Finding header summary */}
        <div className="p-4 rounded-xl bg-surface-subtle border border-border flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs font-mono text-primary-400 bg-primary-950/40 px-2 py-0.5 rounded border border-primary-900/50">
                {finding.ruleId}
              </span>
              <span className="text-xs text-text-muted">en</span>
              <span className="text-xs font-mono text-text">{finding.location}</span>
            </div>
            <h3 className="text-sm font-medium text-white">{finding.title}</h3>
          </div>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => fetchPlaybook()}
            disabled={loading}
            className="flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Regenerar RAG
          </Button>
        </div>

        {error && <Alert kind="error">{error}</Alert>}

        {loading ? (
          <div className="space-y-4 py-6">
            <div className="flex items-center gap-3 justify-center text-sm text-text-muted">
              <RefreshCw className="w-4 h-4 animate-spin text-primary-400" />
              Recuperando vectores semánticos y generando playbook verificado...
            </div>
            <Skeleton className="h-24 w-full rounded-xl" />
            <Skeleton className="h-32 w-full rounded-xl" />
            <Skeleton className="h-28 w-full rounded-xl" />
          </div>
        ) : playbook ? (
          <div className="space-y-6">
            {/* Causa Raíz */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5 mb-2">
                <BookOpen className="w-4 h-4 text-primary-400" />
                Diagnóstico & Causa Raíz (RAG Grounded)
              </h4>
              <div className="p-3.5 rounded-lg bg-surface border border-border text-sm text-text-subtle leading-relaxed whitespace-pre-line">
                {playbook.rootCauseAnalysis}
              </div>
            </div>

            {/* Impacto en Cumplimiento GRC */}
            {playbook.complianceImpact.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5 mb-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  Impacto en Marcos Normativos (GRC Mappings)
                </h4>
                <div className="flex flex-wrap gap-2">
                  {playbook.complianceImpact.map((c, i) => (
                    <div
                      key={i}
                      className="px-2.5 py-1.5 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-xs text-emerald-300 flex items-center gap-1.5"
                    >
                      <span className="font-semibold">{c.framework}</span>
                      <span className="font-mono bg-emerald-900/40 px-1 rounded">{c.controlCode}</span>
                      <span className="text-emerald-400/80 truncate max-w-xs">{c.title}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Paso a paso de remediación */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5 mb-2">
                <Check className="w-4 h-4 text-primary-400" />
                Plan de Acción Paso a Paso
              </h4>
              <div className="space-y-2">
                {playbook.stepByStepRemediation.map((step, idx) => (
                  <div
                    key={idx}
                    className="flex items-start gap-2.5 text-xs text-text p-2.5 rounded-lg bg-surface-subtle border border-border/60"
                  >
                    <span className="w-5 h-5 rounded-full bg-primary-500/20 text-primary-400 flex items-center justify-center font-bold text-xs shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Code / IaC Snippets */}
            {playbook.codeSnippets.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5 mb-2">
                  <Code2 className="w-4 h-4 text-amber-400" />
                  Código de Remediación / Configuración IaC
                </h4>
                <div className="space-y-3">
                  {playbook.codeSnippets.map((snippet, sIdx) => (
                    <div key={sIdx} className="rounded-xl border border-border overflow-hidden bg-surface">
                      <div className="px-3.5 py-2 bg-surface-subtle border-b border-border flex items-center justify-between text-xs">
                        <span className="font-medium text-text">{snippet.description}</span>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-surface text-amber-400 font-mono text-[10px] border border-border">
                            {snippet.language}
                          </span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(snippet.code, 'snippet', sIdx)}
                            className="flex items-center gap-1 text-[11px] text-text-muted hover:text-white transition-colors"
                          >
                            {copiedSnippetIdx === sIdx ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-emerald-400">Copiado</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span>Copiar</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                      <pre className="p-3.5 text-xs font-mono text-text overflow-x-auto bg-black/40 leading-relaxed">
                        <code>{snippet.code}</code>
                      </pre>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Verification Test */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5 mb-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                Comando de Verificación Técnica (Validation Test)
              </h4>
              <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/10 overflow-hidden">
                <div className="p-3 flex items-center justify-between gap-3 text-xs">
                  <code className="font-mono text-emerald-300 break-all">{playbook.verificationTest.command}</code>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(playbook.verificationTest.command, 'command')}
                    className="flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-200 transition-colors shrink-0"
                  >
                    {copiedCommand ? (
                      <>
                        <Check className="w-3.5 h-3.5" />
                        <span>Copiado</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copiar Comando</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="px-3 py-1.5 bg-emerald-950/30 border-t border-emerald-500/10 text-[11px] text-text-muted">
                  <span className="font-semibold text-emerald-400/90">Resultado esperado:</span>{' '}
                  {playbook.verificationTest.expectedResult}
                </div>
              </div>
            </div>

            {/* Grounded Citations */}
            {playbook.groundedCitations.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5 mb-2">
                  <ExternalLink className="w-3.5 h-3.5 text-primary-400" />
                  Fuentes Vectoriales Consultadas (pgvector Citations)
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {playbook.groundedCitations.map((cite, cIdx) => (
                    <div
                      key={cIdx}
                      className="p-2.5 rounded-lg bg-surface border border-border/60 text-xs flex items-center justify-between"
                    >
                      <div className="truncate mr-2">
                        <div className="font-mono text-[11px] text-primary-400">{cite.sourceId}</div>
                        <div className="text-text-muted truncate text-[11px]">{cite.title}</div>
                      </div>
                      <span className="px-1.5 py-0.5 rounded bg-surface-subtle border border-border text-[10px] text-emerald-400 shrink-0 font-mono">
                        {(cite.similarityScore * 100).toFixed(0)}% match
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : null}

        <div className="pt-4 border-t border-border flex justify-end">
          <Button variant="secondary" onClick={onClose}>
            Cerrar Copilot
          </Button>
        </div>
      </div>
    </Modal>
  );
}
