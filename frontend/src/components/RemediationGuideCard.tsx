import { Check, Copy, ExternalLink, Shield, Terminal, Wrench } from 'lucide-react';
import { useState } from 'react';
import type { RemediationGuide } from '@/lib/types';

export function RemediationGuideCard({ guide }: { guide: RemediationGuide }) {
  const [activePlatformIndex, setActivePlatformIndex] = useState(0);
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState(false);

  const snippets = guide.snippets ?? [];
  const currentSnippet = snippets[activePlatformIndex] ?? snippets[0];

  const handleCopyCode = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2000);
    } catch {
      // ignore
    }
  };

  const handleCopyCommand = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedCommand(true);
      setTimeout(() => setCopiedCommand(false), 2000);
    } catch {
      // ignore
    }
  };

  return (
    <div className="mt-4 rounded-xl border border-accent/20 bg-accent/5 p-4 text-ink">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-accent/15 pb-3">
        <div className="flex items-center gap-2">
          <Wrench className="size-4 text-accent" />
          <h4 className="font-semibold text-sm text-ink">Guía de Remediación Técnica</h4>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          {guide.owasp ? (
            <span
              className="inline-flex items-center gap-1 rounded-md bg-accent/10 px-2 py-0.5 font-medium text-accent-strong"
              title="Estándar OWASP"
            >
              <Shield className="size-3" />
              {guide.owasp}
            </span>
          ) : null}
          {guide.cwe ? (
            <span
              className="inline-flex items-center gap-1 rounded-md bg-surface-2 px-2 py-0.5 font-medium text-ink-2"
              title="Clasificación CWE"
            >
              <ExternalLink className="size-3 text-muted" />
              {guide.cwe}
            </span>
          ) : null}
        </div>
      </div>

      <p className="mt-2.5 text-xs text-ink-2 leading-relaxed">{guide.summary}</p>

      {snippets.length > 0 ? (
        <div className="mt-3.5 space-y-2.5">
          {snippets.length > 1 ? (
            <div className="flex flex-wrap gap-1.5 border-b border-border/50 pb-2">
              {snippets.map((snip, idx) => (
                <button
                  key={snip.platform}
                  type="button"
                  onClick={() => setActivePlatformIndex(idx)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                    activePlatformIndex === idx
                      ? 'bg-accent text-white shadow-xs'
                      : 'bg-surface-2 text-ink-2 hover:bg-border/60 hover:text-ink'
                  }`}
                >
                  {snip.platform}
                </button>
              ))}
            </div>
          ) : null}

          {currentSnippet ? (
            <div>
              <p className="text-[11px] font-medium text-muted mb-1.5">{currentSnippet.description}</p>
              <div className="relative rounded-lg border border-border bg-[#18181b] p-3 font-mono text-xs text-zinc-100 dark:bg-black">
                <button
                  type="button"
                  onClick={() => handleCopyCode(currentSnippet.code)}
                  className="absolute top-2.5 right-2.5 inline-flex items-center gap-1 rounded-md bg-zinc-800 px-2 py-1 text-[11px] font-sans font-medium text-zinc-300 hover:bg-zinc-700 hover:text-white"
                  title="Copiar snippet de configuración"
                >
                  {copiedSnippet ? (
                    <>
                      <Check className="size-3 text-emerald-400" /> ¡Copiado!
                    </>
                  ) : (
                    <>
                      <Copy className="size-3" /> Copiar código
                    </>
                  )}
                </button>
                <pre className="overflow-x-auto pr-24 whitespace-pre-wrap">{currentSnippet.code}</pre>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {guide.verificationCommand ? (
        <div className="mt-3.5 pt-3 border-t border-accent/15">
          <div className="flex items-center justify-between gap-2 mb-1.5">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink">
              <Terminal className="size-3.5 text-accent" />
              Comando de verificación rápida:
            </span>
            <button
              type="button"
              onClick={() => handleCopyCommand(guide.verificationCommand!)}
              className="inline-flex items-center gap-1 text-[11px] font-medium text-accent hover:underline"
            >
              {copiedCommand ? <Check className="size-3 text-emerald-500" /> : <Copy className="size-3" />}
              {copiedCommand ? 'Copiado' : 'Copiar comando'}
            </button>
          </div>
          <div className="rounded-lg bg-surface-2 border border-border px-3 py-2 font-mono text-xs text-ink break-all">
            {guide.verificationCommand}
          </div>
        </div>
      ) : null}
    </div>
  );
}
