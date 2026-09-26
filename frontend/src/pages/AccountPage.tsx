import { Building2, KeyRound, Mail, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useAuth } from '@/auth/useAuth';
import { MfaCard } from '@/components/MfaCard';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { PageHeader } from '@/components/ui/PageHeader';
import { PasswordField } from '@/components/ui/PasswordField';
import { useChangeOwnPassword, useOrganization } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { ROLE_DESCRIPTION, ROLE_LABEL } from '@/lib/format';
import { isStrongPassword } from '@/lib/password';

export function AccountPage() {
  const { user, applySession } = useAuth();
  const org = useOrganization();
  const change = useChangeOwnPassword();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [notice, setNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

  if (!user) return null;

  const mismatch = confirm.length > 0 && confirm !== next;
  const valid = current.length > 0 && isStrongPassword(next) && next === confirm;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    try {
      const res = await change.mutateAsync({ currentPassword: current, newPassword: next });
      applySession(res);
      setCurrent('');
      setNext('');
      setConfirm('');
      setNotice({ kind: 'success', text: 'Contraseña actualizada. Se han cerrado tus sesiones en otros dispositivos.' });
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof ApiError ? err.message : 'No se pudo cambiar la contraseña.' });
    }
  };

  return (
    <>
      <PageHeader title="Mi cuenta" description="Tus datos de acceso y la seguridad de tu cuenta." />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Perfil" />
          <CardBody>
            <div className="flex items-center gap-3">
              <span className="flex size-12 items-center justify-center rounded-full bg-accent text-lg font-semibold text-white" aria-hidden>
                {user.fullName.slice(0, 1).toUpperCase()}
              </span>
              <div className="min-w-0">
                <p className="truncate font-semibold text-ink">{user.fullName}</p>
                <p className="truncate text-sm text-ink-2">{ROLE_LABEL[user.role]}</p>
              </div>
            </div>
            <dl className="mt-5 space-y-3 text-sm">
              <div className="flex items-start gap-3">
                <Mail className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />
                <div className="min-w-0">
                  <dt className="text-xs text-muted">Correo</dt>
                  <dd className="truncate text-ink">{user.email}</dd>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <Building2 className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />
                <div className="min-w-0">
                  <dt className="text-xs text-muted">Organización</dt>
                  <dd className="truncate text-ink">{org.data?.name ?? '—'}</dd>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />
                <div>
                  <dt className="text-xs text-muted">Permisos</dt>
                  <dd className="text-ink">{ROLE_DESCRIPTION[user.role]}</dd>
                </div>
              </div>
            </dl>
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Cambiar contraseña" subtitle="Al cambiarla se cerrarán tus sesiones en otros navegadores y dispositivos." />
          <CardBody>
            <form onSubmit={submit} className="max-w-md space-y-4">
              <PasswordField id="pw-current" label="Contraseña actual" value={current} onChange={setCurrent} autoComplete="current-password" showRules={false} />
              <PasswordField id="pw-new" label="Nueva contraseña" value={next} onChange={setNext} />
              <div>
                <PasswordField id="pw-confirm" label="Repite la nueva contraseña" value={confirm} onChange={setConfirm} showRules={false} />
                {mismatch ? <p className="mt-1 text-xs text-critical">Las contraseñas no coinciden.</p> : null}
              </div>
              {notice ? <Alert kind={notice.kind}>{notice.text}</Alert> : null}
              <Button type="submit" icon={<KeyRound className="size-4" />} loading={change.isPending} disabled={!valid}>
                Actualizar contraseña
              </Button>
            </form>
          </CardBody>
        </Card>

        <div className="lg:col-span-3">
          <MfaCard />
        </div>
      </div>
    </>
  );
}
