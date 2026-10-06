import { CircleAlert, CircleCheck, CircleX, Mail } from 'lucide-react';
import type { ReactNode } from 'react';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { timeAgo } from '@/lib/format';
import type { EmailSecuritySummary } from '@/lib/types';

type Level = 'good' | 'warn' | 'bad' | 'na';

const ICON: Record<Level, ReactNode> = {
  good: <CircleCheck className="size-5 shrink-0 text-good" aria-label="Correcto" />,
  warn: <CircleAlert className="size-5 shrink-0 text-[#8a5b00] dark:text-warning" aria-label="Mejorable" />,
  bad: <CircleX className="size-5 shrink-0 text-critical" aria-label="Sin protección" />,
  na: <CircleCheck className="size-5 shrink-0 text-muted" aria-label="No aplica" />,
};

function spfState(s: EmailSecuritySummary): { level: Level; text: string } {
  const spf = s.spf;
  if (spf.records === 0) return { level: s.receivesMail ? 'bad' : 'warn', text: 'No publicado' };
  if (spf.records > 1) return { level: 'bad', text: 'Varios registros: se ignora' };
  if (spf.errors.length > 0) return { level: 'bad', text: spf.errors[0] };
  if (spf.all === '-all') return { level: 'good', text: `Estricto (-all) · ${spf.lookups ?? 0} consultas DNS` };
  if (spf.all === '~all') return { level: 'warn', text: 'Permisivo (~all)' };
  if (spf.all === '+all') return { level: 'bad', text: 'Autoriza a cualquiera (+all)' };
  return { level: 'bad', text: 'Sin política para servidores no autorizados' };
}

function dmarcState(s: EmailSecuritySummary): { level: Level; text: string } {
  const d = s.dmarc;
  if (d.status === 'missing') return { level: 'bad', text: 'No publicado' };
  if (d.status === 'invalid') return { level: 'bad', text: 'Registro no válido' };
  const where = d.inherited ? ` (heredada de ${d.domain})` : '';
  if (d.policy === 'reject') return { level: 'good', text: `Rechaza la suplantación${where}` };
  if (d.policy === 'quarantine') return { level: 'good', text: `Envía a spam la suplantación${where}` };
  return { level: 'warn', text: `Solo monitoriza (p=none)${where}` };
}

function dkimState(s: EmailSecuritySummary): { level: Level; text: string } {
  if (!s.dkim.checked) return { level: 'na', text: 'No aplica: el dominio no recibe correo' };
  if (s.dkim.selectors.length === 0) return { level: 'warn', text: 'No encontrado en los selectores habituales' };
  const weak = s.dkim.selectors.some((k) => k.bits !== null && k.bits < 2048);
  const list = s.dkim.selectors.map((k) => `${k.selector}${k.bits ? ` (${k.bits} bits)` : ''}`).join(', ');
  return { level: weak ? 'warn' : 'good', text: list };
}

function mtaStsState(s: EmailSecuritySummary): { level: Level; text: string } {
  if (!s.receivesMail) return { level: 'na', text: 'No aplica: el dominio no recibe correo' };
  const m = s.mtaSts;
  if (!m || m.status === 'missing') return { level: 'warn', text: 'No publicado (vulnerable a degradación TLS)' };
  if (m.status === 'invalid') return { level: 'bad', text: m.error ?? 'Política MTA-STS o registro inválido' };
  return { level: 'good', text: `Modo ${m.mode ?? 'enforce'}${m.policyId ? ` · ID: ${m.policyId}` : ''}` };
}

function tlsRptState(s: EmailSecuritySummary): { level: Level; text: string } {
  if (!s.receivesMail) return { level: 'na', text: 'No aplica: el dominio no recibe correo' };
  const t = s.tlsRpt;
  if (!t || t.status === 'missing') return { level: 'warn', text: 'No publicado (sin telemetría de fallos TLS)' };
  if (t.status === 'invalid') return { level: 'bad', text: t.error ?? 'Registro TLS-RPT inválido' };
  return { level: 'good', text: `Reportes enviados a: ${t.rua.join(', ')}` };
}

function dnsblState(s: EmailSecuritySummary): { level: Level; text: string } {
  if (!s.receivesMail) return { level: 'na', text: 'No aplica: el dominio no recibe correo' };
  const b = s.dnsbl;
  if (!b || !b.checked) return { level: 'warn', text: 'No evaluado' };
  if (!b.clean && b.listings && b.listings.length > 0) {
    const list = b.listings.map((l) => `${l.ip} en ${l.provider}`).join(', ');
    return { level: 'bad', text: `IP(s) listadas en listas negras: ${list}` };
  }
  return { level: 'good', text: `Limpio · ${b.totalIpsChecked} IP(s) verificadas en Spamhaus y SpamCop` };
}

/** Estado de SPF, DMARC, DKIM, MTA-STS, TLS-RPT y DNSBL según el último escaneo de seguridad del correo. */
export function EmailSecurityCard({ summary, finishedAt }: { summary: EmailSecuritySummary; finishedAt: string | null }) {
  const rows = [
    { name: 'SPF', hint: 'Servidores autorizados a enviar', ...spfState(summary) },
    { name: 'DMARC', hint: 'Qué hacer con la suplantación', ...dmarcState(summary) },
    { name: 'DKIM', hint: 'Firma de los mensajes', ...dkimState(summary) },
    { name: 'MTA-STS', hint: 'Cifrado TLS forzado en tránsito', ...mtaStsState(summary) },
    { name: 'TLS-RPT', hint: 'Telemetría de reportes TLS', ...tlsRptState(summary) },
    { name: 'Reputación IP (DNSBL)', hint: 'Listas negras de servidores MX', ...dnsblState(summary) },
  ];
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <Mail className="size-4 text-accent" aria-hidden /> Seguridad del correo
          </span>
        }
        subtitle={`${summary.receivesMail ? `Recibe correo en ${summary.mx.slice(0, 2).join(', ')}` : 'No recibe correo'}${finishedAt ? ` · ${timeAgo(finishedAt)}` : ''}`}
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
