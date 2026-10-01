import { ExternalLink } from 'lucide-react';
import { SeverityBadge } from '@/components/ui/Badge';
import { cvss } from '@/lib/format';
import type { CveEvidence } from '@/lib/types';

/** CVE de la evidencia de un hallazgo VULN-KNOWN-CVE, con los explotados activamente (KEV) primero. */
export function CveList({ evidence }: { evidence: Record<string, unknown> }) {
  const cves = (Array.isArray(evidence.cves) ? evidence.cves : []) as CveEvidence[];
  const total = typeof evidence.total === 'number' ? evidence.total : cves.length;
  return (
    <div>
      <p className="text-xs font-semibold tracking-wide text-muted uppercase">
        Vulnerabilidades conocidas ({total})
      </p>
      <ul className="mt-1 max-h-72 divide-y divide-line overflow-y-auto rounded-lg border border-border bg-surface">
        {cves.map((c) => (
          <li key={c.id} className="px-3 py-2">
            <div className="flex flex-wrap items-center gap-2">
              <a href={c.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-sm font-medium text-accent hover:underline">
                {c.id} <ExternalLink className="size-3" aria-hidden />
              </a>
              <SeverityBadge severity={c.severity} />
              <span className="tabular text-xs text-ink-2">CVSS {cvss(c.cvss)}</span>
              {c.kev ? (
                <span className="rounded-md bg-critical/10 px-1.5 py-0.5 text-[11px] font-semibold text-critical" title="Catálogo KEV de CISA: explotada activamente">
                  Explotada activamente
                </span>
              ) : null}
            </div>
            {c.description ? <p className="mt-0.5 line-clamp-2 text-xs text-ink-2" title={c.description}>{c.description}</p> : null}
          </li>
        ))}
      </ul>
      {total > cves.length ? <p className="mt-1 text-xs text-muted">Se muestran los {cves.length} más relevantes de {total}.</p> : null}
      {evidence.distroPackage ? (
        <p className="mt-1 text-xs text-muted">Paquete de distribución Linux: algunos CVE pueden estar ya corregidos por backports.</p>
      ) : null}
    </div>
  );
}
