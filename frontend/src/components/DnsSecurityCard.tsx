import { CircleAlert, CircleCheck, CircleX, ShieldCheck } from 'lucide-react';
import type { ReactNode } from 'react';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { timeAgo } from '@/lib/format';
import type { EmailSecuritySummary } from '@/lib/types';

type Level = 'good' | 'warn' | 'bad' | 'na';

const ICON: Record<Level, ReactNode> = {
  good: <CircleCheck className="size-5 shrink-0 text-good" aria-label="Correcto" />,
  warn: <CircleAlert className="size-5 shrink-0 text-[#8a5b00] dark:text-warning" aria-label="Advertencia" />,
  bad: <CircleX className="size-5 shrink-0 text-critical" aria-label="Sin protección" />,
  na: <CircleCheck className="size-5 shrink-0 text-muted" aria-label="No aplica" />,
};

function caaState(s: EmailSecuritySummary): { level: Level; text: string } {
  const caa = s.caa;
  if (!caa || caa.status === 'missing') {
    return {
      level: 'warn',
      text: 'Sin registro CAA (cualquier entidad certificadora pública puede emitir certificados)',
    };
  }
  if (caa.status === 'invalid') {
    return { level: 'bad', text: caa.error ?? 'Registro CAA no válido o parámetro crítico desconocido' };
  }
  const issuers = caa.issue.length > 0 ? caa.issue.join(', ') : 'Ninguna (emisión bloqueada)';
  const where = caa.inherited ? ` (heredado de ${caa.domain})` : '';
  const wild = caa.issuewild.length > 0 ? ` · Wildcard: ${caa.issuewild.join(', ')}` : '';
  const alerts = caa.iodef.length > 0 ? ` · Alertas a: ${caa.iodef.join(', ')}` : '';
  return {
    level: 'good',
    text: `Emisión restringida a: ${issuers}${where}${wild}${alerts}`,
  };
}

function dnssecState(s: EmailSecuritySummary): { level: Level; text: string } {
  const d = s.dnssec;
  if (!d || d.status === 'insecure') {
    return {
      level: 'warn',
      text: 'Zona no firmada (vulnerable a envenenamiento de caché y suplantación DNS)',
    };
  }
  if (d.status === 'bogus') {
    return { level: 'bad', text: d.error ?? 'Firmas criptográficas inconsistentes o expiradas (BOGUS)' };
  }
  if (d.status === 'secure') {
    return {
      level: 'good',
      text: `Validado criptográficamente (AD=true, ${d.dsCount} DS, ${d.dnskeyCount} DNSKEY, ${d.rrsigCount} RRSIG)`,
    };
  }
  return { level: 'warn', text: 'Estado indeterminado de validación DNSSEC' };
}

/** Estado de CAA y DNSSEC según el último escaneo del perímetro de dominio. */
export function DnsSecurityCard({ summary, finishedAt }: { summary: EmailSecuritySummary; finishedAt: string | null }) {
  const rows = [
    { name: 'CAA', hint: 'Control de emisión de certificados SSL/TLS', ...caaState(summary) },
    { name: 'DNSSEC', hint: 'Integridad y autenticidad criptográfica DNS', ...dnssecState(summary) },
  ];

  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <ShieldCheck className="size-4 text-accent" aria-hidden /> Perímetro DNS & Certificados
          </span>
        }
        subtitle={`Protección de infraestructura de nombres${finishedAt ? ` · ${timeAgo(finishedAt)}` : ''}`}
      />
      <CardBody className="px-0 pb-2">
        <ul className="divide-y divide-line">
          {rows.map((r) => (
            <li key={r.name} className="flex items-start gap-3 px-5 py-2.5">
              {ICON[r.level]}
              <div className="min-w-0">
                <p className="text-sm font-medium text-ink">
                  {r.name} <span className="font-normal text-muted">· {r.hint}</span>
                </p>
                <p className="text-sm [overflow-wrap:anywhere] text-ink-2">{r.text}</p>
              </div>
            </li>
          ))}
        </ul>
      </CardBody>
    </Card>
  );
}
