import { ChevronDown, ChevronRight, ScrollText } from 'lucide-react';
import { Fragment, useState } from 'react';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Label, Select } from '@/components/ui/Field';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import { useAuditActions, useAuditLog, useUsers } from '@/hooks/queries';
import { formatDateTime, timeAgo } from '@/lib/format';
import type { AuditEntry } from '@/lib/types';

/** Claves del detalle con nombre legible. */
const DETAIL_LABEL: Record<string, string> = {
  role: 'Rol',
  isActive: 'Activo',
  mfa: 'Con verificación en dos pasos',
  recoveryCode: 'Con código de recuperación',
  recoveryCodesLeft: 'Códigos de recuperación restantes',
  delivery: 'Envío del correo',
  method: 'Método',
  scope: 'Ámbito',
  frequency: 'Frecuencia',
  previous: 'Anterior',
  previousStatus: 'Estado anterior',
  status: 'Estado',
  note: 'Justificación',
  name: 'Nombre',
  minSeverity: 'Severidad mínima',
  type: 'Tipo',
  verificationMethod: 'Verificación',
};

function DetailList({ detail }: { detail: Record<string, unknown> }) {
  const entries = Object.entries(detail).filter(([, v]) => v !== null && v !== undefined);
  if (entries.length === 0) return null;
  return (
    <dl className="grid gap-x-6 gap-y-1 text-xs text-ink-2 sm:grid-cols-2">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt className="inline text-muted">{DETAIL_LABEL[key] ?? key}: </dt>
          <dd className="inline [overflow-wrap:anywhere]">
            {typeof value === 'boolean' ? (value ? 'sí' : 'no') : String(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** RNF-06: quién hizo qué y cuándo. Solo para administradores. */
export function AuditPage() {
  const [action, setAction] = useState('');
  const [actorId, setActorId] = useState('');
  const [page, setPage] = useState(1);
  const [openId, setOpenId] = useState<string | null>(null);
  const q = useAuditLog({ action: action || undefined, actorId: actorId || undefined, page });
  const actions = useAuditActions();
  const users = useUsers();

  const label = (a: AuditEntry) => actions.data?.actions[a.action] ?? a.action;

  const setFilter = (fn: () => void) => {
    fn();
    setPage(1);
  };

  return (
    <>
      <PageHeader
        title="Registro de auditoría"
        description="Quién hizo qué y cuándo: inicios de sesión, usuarios, activos, hallazgos y configuración."
      />
      <Card>
        <div className="flex flex-wrap items-end gap-3 px-5 pt-4 pb-3">
          <div>
            <Label htmlFor="f-action">Acción</Label>
            <Select id="f-action" value={action} onChange={(e) => setFilter(() => setAction(e.target.value))}>
              <option value="">Todas</option>
              {Object.entries(actions.data?.actions ?? {}).map(([key, text]) => (
                <option key={key} value={key}>{text}</option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="f-actor">Usuario</Label>
            <Select id="f-actor" value={actorId} onChange={(e) => setFilter(() => setActorId(e.target.value))}>
              <option value="">Todos</option>
              {(users.data ?? []).map((u) => (
                <option key={u.id} value={u.id}>{u.fullName}</option>
              ))}
            </Select>
          </div>
        </div>

        {q.isPending ? (
          <div className="space-y-2 p-5"><Skeleton className="h-8" /><Skeleton className="h-8" /><Skeleton className="h-8" /></div>
        ) : (q.data?.items.length ?? 0) === 0 ? (
          <EmptyState icon={ScrollText} title="Sin acciones registradas" description="Aquí aparecerán las acciones de los usuarios de tu organización." />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th className="w-8"><span className="sr-only">Detalle</span></Th>
                <Th>Fecha</Th>
                <Th>Acción</Th>
                <Th className="hidden sm:table-cell">Usuario</Th>
                <Th className="hidden md:table-cell">Objeto</Th>
                <Th className="hidden lg:table-cell">IP</Th>
              </tr>
            </thead>
            <tbody>
              {q.data!.items.map((a) => {
                const hasDetail = a.detail && Object.keys(a.detail).length > 0;
                const isOpen = openId === a.id;
                return (
                  <Fragment key={a.id}>
                    <tr
                      className={hasDetail ? 'cursor-pointer hover:bg-surface-2/50' : undefined}
                      onClick={hasDetail ? () => setOpenId(isOpen ? null : a.id) : undefined}
                    >
                      <Td>
                        {hasDetail ? (
                          <button type="button" aria-expanded={isOpen} aria-label={`Detalle de ${label(a)}`} className="text-muted">
                            {isOpen ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
                          </button>
                        ) : null}
                      </Td>
                      <Td className="whitespace-nowrap text-ink-2" title={formatDateTime(a.createdAt)}>{timeAgo(a.createdAt)}</Td>
                      <Td className="font-medium text-ink">{label(a)}</Td>
                      <Td className="hidden max-w-[14rem] sm:table-cell">
                        <span className="block truncate text-ink-2" title={a.actorEmail ?? undefined}>
                          {a.actorName ?? a.actorEmail ?? '—'}
                        </span>
                      </Td>
                      <Td className="hidden max-w-[16rem] truncate text-ink-2 md:table-cell" title={a.targetLabel ?? undefined}>
                        {a.targetLabel ?? '—'}
                      </Td>
                      <Td className="tabular hidden whitespace-nowrap text-xs text-muted lg:table-cell">{a.ip ?? '—'}</Td>
                    </tr>
                    {isOpen && hasDetail ? (
                      <tr className="bg-surface-2/40">
                        <td colSpan={6} className="border-b border-line px-5 py-3">
                          <p className="mb-1 text-xs text-muted sm:hidden">
                            {a.actorName ?? a.actorEmail ?? '—'} · {formatDateTime(a.createdAt)}
                          </p>
                          <DetailList detail={a.detail!} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </Table>
        )}

        {q.data && q.data.meta.totalPages > 1 ? (
          <div className="flex items-center justify-between border-t border-line px-5 py-3 text-sm text-ink-2">
            <span>{q.data.meta.total} acciones · página {q.data.meta.page} de {q.data.meta.totalPages}</span>
            <div className="flex gap-2">
              <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage(page - 1)}>Anterior</Button>
              <Button size="sm" variant="secondary" disabled={page >= q.data.meta.totalPages} onClick={() => setPage(page + 1)}>Siguiente</Button>
            </div>
          </div>
        ) : null}
      </Card>
    </>
  );
}
