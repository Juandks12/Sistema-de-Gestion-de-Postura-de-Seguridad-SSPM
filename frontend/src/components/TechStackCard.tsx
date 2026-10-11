import { AlertTriangle, Binary, Box, CheckCircle2, Cloud, Cpu, Globe, Layers, Server } from 'lucide-react';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import type { DetectedTechnology } from '@/lib/types';

function categoryIcon(category: string) {
  switch (category) {
    case 'Web Server':
      return <Server className="size-4 text-blue-500" />;
    case 'Framework':
      return <Box className="size-4 text-purple-500" />;
    case 'CMS':
      return <Globe className="size-4 text-emerald-500" />;
    case 'Programming Language':
      return <Binary className="size-4 text-amber-500" />;
    case 'Frontend Library':
      return <Layers className="size-4 text-indigo-500" />;
    case 'CDN/Proxy':
      return <Cloud className="size-4 text-cyan-500" />;
    default:
      return <Cpu className="size-4 text-muted" />;
  }
}

export function TechStackCard({ technologies = [] }: { technologies?: DetectedTechnology[] }) {
  const hasEol = technologies.some((t) => t.eol);

  return (
    <Card>
      <CardHeader
        title="Tecnologías y Stack Web"
        subtitle="Componentes, servidores, frameworks y librerías detectados en las respuestas HTTP del activo."
        action={
          technologies.length > 0 ? (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-surface-2 px-2.5 py-0.5 text-xs font-medium text-ink-2">
              <Layers className="size-3.5 text-muted" />
              {technologies.length} componente{technologies.length === 1 ? '' : 's'}
            </span>
          ) : null
        }
      />
      <CardBody>
        {technologies.length === 0 ? (
          <EmptyState
            icon={Cpu}
            title="Sin tecnologías detectadas"
            description="Ejecuta una auditoría de cabeceras web para inspeccionar firmas de servidor, frameworks y componentes."
          />
        ) : (
          <div className="space-y-4">
            {hasEol ? (
              <div className="flex items-center gap-2 rounded-lg border border-critical/30 bg-critical/10 p-3 text-xs text-critical">
                <AlertTriangle className="size-4 shrink-0" />
                <p>
                  <strong>Atención:</strong> Se identificaron uno o más componentes en <strong>Fin de Soporte (EOL)</strong>. Estas versiones ya no reciben actualizaciones de seguridad del fabricante.
                </p>
              </div>
            ) : null}

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {technologies.map((tech) => (
                <div
                  key={`${tech.name}-${tech.version ?? 'any'}`}
                  className={`flex flex-col justify-between rounded-lg border p-3.5 transition-shadow hover:shadow-sm ${
                    tech.eol ? 'border-critical/40 bg-critical/5' : 'border-border bg-surface'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-surface-2">
                        {categoryIcon(tech.category)}
                      </div>
                      <div className="min-w-0">
                        <p className="truncate font-semibold text-sm text-ink">{tech.name}</p>
                        <p className="truncate text-xs text-muted">{tech.category}</p>
                      </div>
                    </div>

                    {tech.version ? (
                      <span className="inline-flex items-center rounded-md border border-border bg-surface-2 px-2 py-0.5 text-xs font-mono font-medium text-ink">
                        v{tech.version}
                      </span>
                    ) : null}
                  </div>

                  <div className="mt-3 flex items-center justify-between gap-2 pt-2 border-t border-line text-xs">
                    {tech.eol ? (
                      <span
                        className="inline-flex items-center gap-1 font-semibold text-critical"
                        title={tech.eolNotice ?? 'Tecnología en fin de soporte'}
                      >
                        <AlertTriangle className="size-3" /> EOL
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-good-text font-medium text-[11px]">
                        <CheckCircle2 className="size-3 text-good" /> Activo
                      </span>
                    )}

                    <span className="text-[11px] text-muted">Confianza {tech.confidence}%</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
