import { CalendarClock, Mail, Plus, Send, Trash2, Webhook } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { SeverityBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input, Label, Select } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { PageHeader } from '@/components/ui/PageHeader';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import {
  useAlertChannels,
  useCreateChannel,
  useDeleteChannel,
  useMonitoring,
  useTestChannel,
  useUpdateChannel,
  useUpdateMonitoring,
} from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import { FREQUENCY_DESCRIPTION, FREQUENCY_LABEL, SEVERITY_LABEL, SEVERITY_ORDER, formatDateTime, timeAgo } from '@/lib/format';
import type { AlertChannel, AlertChannelType, MonitoringFrequency, Severity } from '@/lib/types';

const FREQUENCIES: MonitoringFrequency[] = ['OFF', 'DAILY', 'WEEKLY'];

export function SettingsPage() {
  const { hasRole } = useAuth();
  if (!hasRole('ADMIN')) {
    return <EmptyState icon={CalendarClock} title="Solo los administradores pueden cambiar la configuración" />;
  }
  return (
    <>
      <PageHeader title="Configuración" description="Monitoreo continuo de los activos y canales por los que se notifican las alertas." />
      <MonitoringCard />
      <ChannelsCard />
    </>
  );
}

function MonitoringCard() {
  const q = useMonitoring();
  const update = useUpdateMonitoring();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<MonitoringFrequency | null>(null);

  const change = async (frequency: MonitoringFrequency) => {
    setError(null);
    setPending(frequency);
    try {
      await update.mutateAsync(frequency);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo guardar la frecuencia.');
    } finally {
      setPending(null);
    }
  };

  const data = q.data;
  const monitored = data?.assets.filter((a) => a.monitored) ?? [];
  // Selección optimista: se marca al instante mientras se guarda.
  const selected = pending ?? data?.frequency;

  return (
    <Card>
      <CardHeader title="Monitoreo continuo" subtitle="Reaudita automáticamente todos los activos activos: puertos, cabeceras, certificado y rutas sensibles." />
      <CardBody>
        {q.isPending || !data ? (
          <Skeleton className="h-24" />
        ) : (
          <>
            <fieldset>
              <legend className="sr-only">Frecuencia</legend>
              <div className="grid gap-2 sm:grid-cols-3">
                {FREQUENCIES.map((f) => (
                  <label
                    key={f}
                    className={cn(
                      'flex cursor-pointer flex-col rounded-lg border p-3 transition-colors',
                      selected === f ? 'border-accent bg-accent/8' : 'border-border hover:bg-surface-2',
                    )}
                  >
                    <span className="flex items-center gap-2">
                      <input type="radio" name="frequency" value={f} checked={selected === f} onChange={() => change(f)} disabled={pending !== null} className="accent-[var(--accent)]" />
                      <span className="text-sm font-medium text-ink">{FREQUENCY_LABEL[f]}</span>
                    </span>
                    <span className="mt-1 pl-6 text-xs text-ink-2">{FREQUENCY_DESCRIPTION[f]}</span>
                  </label>
                ))}
              </div>
            </fieldset>
            {error ? <Alert kind="error" className="mt-3">{error}</Alert> : null}
            {!data.schedulerEnabled && data.frequency !== 'OFF' ? (
              <Alert kind="info" className="mt-3">El planificador está desactivado en este servidor (SCHEDULER_ENABLED=false): la frecuencia se guarda pero no se ejecutará hasta activarlo.</Alert>
            ) : null}

            {data.frequency !== 'OFF' ? (
              <div className="mt-4">
                <p className="mb-2 text-xs font-semibold tracking-wide text-muted uppercase">
                  {monitored.length} activo(s) monitoreado(s){data.lastScheduledScanAt ? ` · última auditoría programada ${timeAgo(data.lastScheduledScanAt)}` : ''}
                </p>
                <ul className="divide-y divide-line rounded-lg border border-border">
                  {data.assets.map((a) => (
                    <li key={a.id} className="flex items-center gap-3 px-3 py-2 text-sm">
                      <span className="min-w-0 flex-1 truncate text-ink">{a.name ?? a.value}</span>
                      <span className="shrink-0 text-xs text-ink-2">
                        {!a.monitored
                          ? !a.isActive
                            ? 'Inactivo: excluido'
                            : !a.verifiedAt
                              ? 'Sin verificar: excluido hasta verificar su propiedad'
                              : 'Sin autorización de escaneo'
                          : a.due
                            ? 'Pendiente: se auditará en breve'
                            : `Próxima: ${formatDateTime(a.nextRunAt)}`}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </>
        )}
      </CardBody>
    </Card>
  );
}

function ChannelsCard() {
  const q = useAlertChannels();
  const update = useUpdateChannel();
  const remove = useDeleteChannel();
  const test = useTestChannel();
  const [creating, setCreating] = useState(false);
  const [notice, setNotice] = useState<{ kind: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AlertChannel | null>(null);

  const runTest = async (c: AlertChannel) => {
    setNotice(null);
    try {
      const r = await test.mutateAsync(c.id);
      setNotice(
        r.status === 'SENT'
          ? { kind: 'success', text: `Notificación de prueba enviada por "${c.name}".` }
          : { kind: r.status === 'SKIPPED' ? 'info' : 'error', text: `"${c.name}": ${r.error ?? 'no se pudo enviar'}` },
      );
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof ApiError ? err.message : 'No se pudo enviar la prueba.' });
    }
  };

  const toggle = async (c: AlertChannel) => {
    setNotice(null);
    try {
      await update.mutateAsync({ id: c.id, isActive: !c.isActive });
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof ApiError ? err.message : 'No se pudo actualizar el canal.' });
    }
  };

  const channels = q.data?.items ?? [];

  return (
    <Card className="mt-4">
      <CardHeader
        title="Canales de notificación"
        subtitle="Dónde se avisa cuando se genera una alerta. Cada canal recibe las alertas desde la severidad mínima que elijas."
        action={<Button size="sm" icon={<Plus className="size-4" />} onClick={() => setCreating(true)}>Nuevo canal</Button>}
      />
      {q.data && !q.data.emailEnabled ? (
        <div className="px-5 pb-3">
          <Alert kind="info">El servidor de correo (SMTP) no está configurado: los canales de correo se guardan pero sus envíos se omiten hasta configurarlo.</Alert>
        </div>
      ) : null}
      {notice ? <div className="px-5 pb-3"><Alert kind={notice.kind}>{notice.text}</Alert></div> : null}
      {q.isPending ? (
        <div className="px-5 pb-5"><Skeleton className="h-16" /></div>
      ) : channels.length === 0 ? (
        <EmptyState
          icon={Send}
          title="Sin canales configurados"
          description="Las alertas se verán solo en la plataforma. Añade un correo o un webhook de Slack, Discord o tu propio sistema."
          action={<Button size="sm" onClick={() => setCreating(true)}>Añadir canal</Button>}
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Canal</Th>
              <Th className="hidden md:table-cell">Desde</Th>
              <Th className="hidden sm:table-cell">Último envío</Th>
              <Th className="w-1" />
            </tr>
          </thead>
          <tbody>
            {channels.map((c) => (
              <tr key={c.id} className={c.isActive ? '' : 'opacity-60'}>
                <Td>
                  <p className="flex items-center gap-2 font-medium text-ink">
                    {c.type === 'EMAIL' ? <Mail className="size-4 text-muted" aria-hidden /> : <Webhook className="size-4 text-muted" aria-hidden />}
                    {c.name}
                    {!c.isActive ? <span className="rounded-md bg-surface-2 px-1.5 py-0.5 text-xs font-normal text-muted">Pausado</span> : null}
                  </p>
                  <p className="mt-0.5 truncate pl-6 text-xs text-muted" title={c.target}>{c.target}</p>
                </Td>
                <Td className="hidden md:table-cell"><SeverityBadge severity={c.minSeverity} /></Td>
                <Td className="hidden text-xs sm:table-cell">
                  {c.lastDeliveryAt ? (
                    <>
                      <span className={cn('font-medium', c.lastDeliveryStatus === 'SENT' ? 'text-good-text' : c.lastDeliveryStatus === 'FAILED' ? 'text-critical' : 'text-ink-2')}>
                        {c.lastDeliveryStatus === 'SENT' ? 'Enviado' : c.lastDeliveryStatus === 'FAILED' ? 'Error' : 'Omitido'}
                      </span>
                      <span className="text-muted"> · {timeAgo(c.lastDeliveryAt)}</span>
                      {c.lastDeliveryError ? <p className="max-w-64 truncate text-muted" title={c.lastDeliveryError}>{c.lastDeliveryError}</p> : null}
                    </>
                  ) : <span className="text-muted">Nunca</span>}
                </Td>
                <Td className="text-right">
                  <div className="flex justify-end gap-1">
                    <Button size="sm" variant="ghost" onClick={() => runTest(c)} disabled={test.isPending} title="Enviar prueba">
                      <Send className="size-4" /><span className="hidden lg:inline">Probar</span>
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => toggle(c)} disabled={update.isPending}>
                      {c.isActive ? 'Pausar' : 'Activar'}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setConfirmDelete(c)} aria-label={`Eliminar ${c.name}`}>
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {creating ? <ChannelModal onClose={() => setCreating(false)} /> : null}
      {confirmDelete ? (
        <Modal
          open
          onClose={() => setConfirmDelete(null)}
          title="Eliminar canal"
          footer={
            <>
              <Button variant="secondary" onClick={() => setConfirmDelete(null)}>Cancelar</Button>
              <Button
                variant="danger"
                loading={remove.isPending}
                onClick={async () => {
                  await remove.mutateAsync(confirmDelete.id).catch(() => undefined);
                  setConfirmDelete(null);
                }}
              >
                Eliminar
              </Button>
            </>
          }
        >
          <p className="text-sm text-ink-2">Las alertas dejarán de enviarse por <span className="font-medium text-ink">{confirmDelete.name}</span>. Las alertas ya generadas se conservan.</p>
        </Modal>
      ) : null}
    </Card>
  );
}

function ChannelModal({ onClose }: { onClose: () => void }) {
  const create = useCreateChannel();
  const [type, setType] = useState<AlertChannelType>('WEBHOOK');
  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [minSeverity, setMinSeverity] = useState<Severity>('HIGH');
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await create.mutateAsync({ type, name: name.trim(), target: target.trim(), minSeverity });
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo crear el canal.');
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Nuevo canal de notificación"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancelar</Button>
          <Button type="submit" form="channel-form" loading={create.isPending} disabled={!name.trim() || !target.trim()}>Guardar</Button>
        </>
      }
    >
      <form id="channel-form" onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-2 gap-2">
          {(['WEBHOOK', 'EMAIL'] as AlertChannelType[]).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setType(t)}
              aria-pressed={type === t}
              className={cn('flex items-center gap-2 rounded-lg border px-3 py-2 text-sm', type === t ? 'border-accent bg-accent/8 text-ink' : 'border-border text-ink-2 hover:bg-surface-2')}
            >
              {t === 'EMAIL' ? <Mail className="size-4" /> : <Webhook className="size-4" />}
              {t === 'EMAIL' ? 'Correo electrónico' : 'Webhook'}
            </button>
          ))}
        </div>
        <div>
          <Label htmlFor="ch-name">Nombre</Label>
          <Input id="ch-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder={type === 'EMAIL' ? 'Equipo de TI' : 'Canal #seguridad en Slack'} required />
        </div>
        <div>
          <Label htmlFor="ch-target" hint={type === 'EMAIL' ? '(separados por coma)' : undefined}>{type === 'EMAIL' ? 'Destinatarios' : 'URL del webhook'}</Label>
          <Input
            id="ch-target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            maxLength={1000}
            type={type === 'EMAIL' ? 'text' : 'url'}
            placeholder={type === 'EMAIL' ? 'ti@empresa.com, seguridad@empresa.com' : 'https://hooks.slack.com/services/…'}
            required
          />
          <p className="mt-1 text-xs text-muted">
            {type === 'EMAIL'
              ? 'Hasta 20 direcciones.'
              : 'Solo HTTPS. Los webhooks de Slack y Discord se formatean automáticamente; cualquier otra URL recibe un JSON con la alerta. La URL se guarda y se muestra enmascarada.'}
          </p>
        </div>
        <div>
          <Label htmlFor="ch-severity">Notificar desde</Label>
          <Select id="ch-severity" value={minSeverity} onChange={(e) => setMinSeverity(e.target.value as Severity)}>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {s === 'INFO' ? 'Todas las severidades' : `Severidad ${SEVERITY_LABEL[s].toLowerCase()}${s !== 'CRITICAL' ? ' o superior' : ''}`}
              </option>
            ))}
          </Select>
        </div>
        {error ? <Alert kind="error">{error}</Alert> : null}
      </form>
    </Modal>
  );
}
