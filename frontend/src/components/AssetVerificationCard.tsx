import { BadgeCheck, Check, CircleX, Copy, FileText, Globe, ShieldQuestion } from 'lucide-react';
import { useState } from 'react';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Skeleton } from '@/components/ui/Spinner';
import { useAssetVerification, useVerifyAsset } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import { formatDateTime, timeAgo } from '@/lib/format';
import type { AssetVerification, VerificationMethod } from '@/lib/types';

const METHOD_LABEL: Record<VerificationMethod, string> = {
  DNS_TXT: 'registro DNS TXT',
  HTTP_FILE: 'archivo de verificación',
  INHERITED: 'dominio superior verificado',
  PRE_AUTHORIZED: 'objetivo de prueba pre-autorizado',
};

function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="min-w-0">
      <p className="text-xs text-muted">{label}</p>
      <div className="mt-0.5 flex items-center gap-2 rounded-lg border border-border bg-surface-2/60 py-1 pr-1 pl-3">
        <code className="min-w-0 flex-1 truncate text-[13px] text-ink" title={value}>{value}</code>
        <Button size="sm" variant="ghost" onClick={copy} aria-label={`Copiar ${label.toLowerCase()}`} title="Copiar">
          {copied ? <Check className="size-4 text-good" /> : <Copy className="size-4" />}
        </Button>
      </div>
    </div>
  );
}

function Instructions({ v }: { v: AssetVerification }) {
  return (
    <div className="grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-2">
      {v.dns ? (
        <section className="min-w-0 rounded-lg border border-border p-4">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-ink">
            <Globe className="size-4 text-accent" aria-hidden /> Opción 1 · Registro DNS (recomendada)
          </h3>
          <p className="mt-1 text-sm text-ink-2">Crea un registro TXT en el DNS del dominio. Puede tardar unos minutos en propagarse.</p>
          <div className="mt-3 space-y-2">
            <CopyValue label="Nombre (host)" value={v.dns.recordName} />
            <CopyValue label="Tipo" value="TXT" />
            <CopyValue label="Valor" value={v.dns.value} />
          </div>
          {v.dns.alternatives.length > 0 ? (
            <p className="mt-2 text-xs [overflow-wrap:anywhere] text-muted">
              También vale en un dominio superior, que cubre todos sus subdominios: {v.dns.alternatives.join(', ')}.
            </p>
          ) : null}
        </section>
      ) : null}
      <section className="min-w-0 rounded-lg border border-border p-4">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-ink">
          <FileText className="size-4 text-accent" aria-hidden /> {v.dns ? 'Opción 2 · ' : ''}Archivo de verificación
        </h3>
        <p className="mt-1 text-sm text-ink-2">
          Publica un archivo de texto con este contenido exacto. Debe responder directamente (sin redirecciones) en una de estas direcciones:
        </p>
        <ul className="mt-2 space-y-0.5 text-xs text-ink-2">
          {v.file.urls.map((u) => (
            <li key={u} className="truncate font-mono" title={u}>{u}</li>
          ))}
        </ul>
        <div className="mt-3">
          <CopyValue label="Contenido del archivo" value={v.file.content} />
        </div>
      </section>
    </div>
  );
}

/**
 * Verificación de propiedad del activo (sección 1.6.3). Sin ella la plataforma
 * no permite escanearlo.
 */
export function AssetVerificationCard({ assetId, canEdit }: { assetId: string; canEdit: boolean }) {
  const q = useAssetVerification(assetId);
  const verify = useVerifyAsset();
  const [showInstructions, setShowInstructions] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (q.isPending) return <Skeleton className="mb-4 h-24" />;
  if (!q.data) return null;
  const v = q.data;
  const result = verify.data;

  const run = async () => {
    setError(null);
    try {
      await verify.mutateAsync({ id: assetId });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo comprobar la verificación.');
    }
  };

  if (v.verified) {
    return (
      <Card className="mb-4">
        <CardBody className="flex flex-wrap items-center gap-3 py-4">
          <BadgeCheck className="size-5 shrink-0 text-good" aria-hidden />
          <p className="min-w-0 flex-1 text-sm text-ink-2">
            <span className="font-medium text-ink">Propiedad verificada</span> mediante {v.method ? METHOD_LABEL[v.method] : 'verificación'}
            {v.scope && v.scope !== v.value ? ` (${v.scope})` : ''} · {timeAgo(v.verifiedAt)}
          </p>
          <Button size="sm" variant="ghost" onClick={() => setShowInstructions((s) => !s)}>
            {showInstructions ? 'Ocultar instrucciones' : 'Ver instrucciones'}
          </Button>
          {showInstructions ? <div className="w-full pt-2"><Instructions v={v} /></div> : null}
        </CardBody>
      </Card>
    );
  }

  return (
    <Card className="mb-4 border-warning/60">
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <ShieldQuestion className="size-5 text-[#8a5b00] dark:text-warning" aria-hidden /> Verifica que este activo es de tu organización
          </span>
        }
        subtitle={
          v.required
            ? 'Para evitar que la plataforma se use contra sistemas de terceros, no se puede escanear un activo hasta demostrar que lo controláis.'
            : 'La verificación está desactivada en este servidor (entorno de pruebas), pero conviene hacerla antes de pasar a producción.'
        }
      />
      <CardBody>
        <Instructions v={v} />
        <div className="mt-4 flex flex-wrap items-center gap-3">
          {canEdit ? (
            <Button icon={<BadgeCheck className="size-4" />} onClick={run} loading={verify.isPending}>
              Comprobar ahora
            </Button>
          ) : (
            <p className="text-sm text-ink-2">Pide a un administrador o analista que publique la prueba y la compruebe.</p>
          )}
          {v.checkedAt ? <span className="text-xs text-muted">Última comprobación: {formatDateTime(v.checkedAt)}</span> : null}
        </div>
        {error ? <Alert kind="error" className="mt-3">{error}</Alert> : null}
        {result && !result.success && result.attempts ? (
          <div className="mt-3">
            <Alert kind="error">Todavía no se encuentra la prueba. Si acabas de crear el registro DNS, espera unos minutos y vuelve a comprobar.</Alert>
            <ul className="mt-2 space-y-1">
              {result.attempts.map((a) => (
                <li key={`${a.method}-${a.target}`} className="flex items-start gap-2 text-xs">
                  {a.ok ? <Check className="mt-0.5 size-3.5 shrink-0 text-good" /> : <CircleX className="mt-0.5 size-3.5 shrink-0 text-critical" />}
                  <span className={cn('min-w-0', a.ok ? 'text-ink' : 'text-ink-2')}>
                    <span className="font-mono">{a.target}</span> — {a.detail}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ) : !result && v.error ? (
          <p className="mt-3 text-xs text-muted">Último resultado: {v.error}</p>
        ) : null}
      </CardBody>
    </Card>
  );
}
