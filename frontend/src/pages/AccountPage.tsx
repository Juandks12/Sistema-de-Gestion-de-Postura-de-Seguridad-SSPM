import { Building2, CheckCircle2, Clock, KeyRound, Mail, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useAuth } from '@/auth/useAuth';
import { MfaCard } from '@/components/MfaCard';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Input, Label } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { PageHeader } from '@/components/ui/PageHeader';
import { PasswordField } from '@/components/ui/PasswordField';
import {
  useCancelPendingEmail,
  useChangeOwnPassword,
  useOrganization,
  useRequestEmailChange,
  useResendVerification,
} from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { ROLE_DESCRIPTION, ROLE_LABEL } from '@/lib/format';
import { isStrongPassword } from '@/lib/password';

export function AccountPage() {
  const { user, applySession, refreshUser } = useAuth();
  const org = useOrganization();
  const change = useChangeOwnPassword();
  const resendVerification = useResendVerification();
  const requestEmailChange = useRequestEmailChange();
  const cancelPendingEmail = useCancelPendingEmail();

  // Cambio de contraseña
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [notice, setNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

  // Verificación y cambio de email
  const [emailNotice, setEmailNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const [changeEmailOpen, setChangeEmailOpen] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [emailPassword, setEmailPassword] = useState('');
  const [modalNotice, setModalNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

  if (!user) return null;

  const mismatch = confirm.length > 0 && confirm !== next;
  const valid = current.length > 0 && isStrongPassword(next) && next === confirm;

  const submitPassword = async (e: FormEvent) => {
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

  const handleResendVerification = async () => {
    setEmailNotice(null);
    try {
      const res = await resendVerification.mutateAsync();
      setEmailNotice({ kind: 'success', text: res.message });
    } catch (err) {
      setEmailNotice({
        kind: 'error',
        text: err instanceof ApiError ? err.message : 'No se pudo reenviar la verificación.',
      });
    }
  };

  const handleCancelPendingEmail = async () => {
    setEmailNotice(null);
    try {
      const res = await cancelPendingEmail.mutateAsync();
      await refreshUser();
      setEmailNotice({ kind: 'success', text: res.message });
    } catch (err) {
      setEmailNotice({
        kind: 'error',
        text: err instanceof ApiError ? err.message : 'No se pudo cancelar el cambio de correo.',
      });
    }
  };

  const submitEmailChange = async (e: FormEvent) => {
    e.preventDefault();
    setModalNotice(null);
    try {
      const res = await requestEmailChange.mutateAsync({
        newEmail: newEmail.trim(),
        currentPassword: emailPassword,
      });
      await refreshUser();
      setNewEmail('');
      setEmailPassword('');
      setChangeEmailOpen(false);
      setEmailNotice({
        kind: 'success',
        text: res.message || 'Solicitud procesada correctamente.',
      });
    } catch (err) {
      setModalNotice({
        kind: 'error',
        text: err instanceof ApiError ? err.message : 'No se pudo solicitar el cambio de correo electrónico.',
      });
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
              <span
                className="flex size-12 items-center justify-center rounded-full bg-accent text-lg font-semibold text-white"
                aria-hidden
              >
                {user.fullName.slice(0, 1).toUpperCase()}
              </span>
              <div className="min-w-0">
                <p className="truncate font-semibold text-ink">{user.fullName}</p>
                <p className="truncate text-sm text-ink-2">{ROLE_LABEL[user.role]}</p>
              </div>
            </div>

            <dl className="mt-5 space-y-4 text-sm">
              <div className="flex items-start gap-3">
                <Mail className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />
                <div className="min-w-0 flex-1">
                  <dt className="text-xs text-muted">Correo electrónico</dt>
                  <dd className="mt-0.5 flex flex-wrap items-center gap-2">
                    <span className="truncate font-medium text-ink">{user.email}</span>
                    {user.emailVerified ? (
                      <span className="inline-flex items-center gap-1 rounded-md bg-good/12 px-2 py-0.5 text-[11px] font-semibold text-good-text">
                        <CheckCircle2 className="size-3" /> Verificado
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-md bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-500 dark:text-amber-400">
                        <Clock className="size-3" /> Sin verificar
                      </span>
                    )}
                  </dd>

                  <div className="mt-3 flex flex-wrap gap-2">
                    {!user.emailVerified && (
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={handleResendVerification}
                        loading={resendVerification.isPending}
                      >
                        Reenviar verificación
                      </Button>
                    )}
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        setModalNotice(null);
                        setChangeEmailOpen(true);
                      }}
                    >
                      Cambiar correo
                    </Button>
                  </div>

                  {user.pendingEmail && (
                    <div className="mt-3 rounded-lg border border-amber-500/20 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300">
                      <p className="font-semibold">Cambio de correo pendiente:</p>
                      <p className="mt-1">
                        Se enviará la confirmación a <strong>{user.pendingEmail}</strong>. Hasta que se confirme, tu correo sigue siendo <strong>{user.email}</strong>.
                      </p>
                      <div className="mt-2">
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="text-critical hover:bg-critical/10"
                          onClick={handleCancelPendingEmail}
                          loading={cancelPendingEmail.isPending}
                        >
                          Cancelar solicitud
                        </Button>
                      </div>
                    </div>
                  )}

                  {emailNotice && (
                    <div className="mt-3">
                      <Alert kind={emailNotice.kind}>{emailNotice.text}</Alert>
                    </div>
                  )}
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
          <CardHeader
            title="Cambiar contraseña"
            subtitle="Al cambiarla se cerrarán tus sesiones en otros navegadores y dispositivos."
          />
          <CardBody>
            <form onSubmit={submitPassword} className="max-w-md space-y-4">
              <PasswordField
                id="pw-current"
                label="Contraseña actual"
                value={current}
                onChange={setCurrent}
                autoComplete="current-password"
                showRules={false}
              />
              <PasswordField id="pw-new" label="Nueva contraseña" value={next} onChange={setNext} />
              <div>
                <PasswordField
                  id="pw-confirm"
                  label="Repite la nueva contraseña"
                  value={confirm}
                  onChange={setConfirm}
                  showRules={false}
                />
                {mismatch ? <p className="mt-1 text-xs text-critical">Las contraseñas no coinciden.</p> : null}
              </div>
              {notice ? <Alert kind={notice.kind}>{notice.text}</Alert> : null}
              <Button
                type="submit"
                icon={<KeyRound className="size-4" />}
                loading={change.isPending}
                disabled={!valid}
              >
                Actualizar contraseña
              </Button>
            </form>
          </CardBody>
        </Card>

        <div className="lg:col-span-3">
          <MfaCard />
        </div>
      </div>

      <Modal
        open={changeEmailOpen}
        onClose={() => setChangeEmailOpen(false)}
        title="Cambiar correo electrónico"
        footer={
          <>
            <Button variant="ghost" onClick={() => setChangeEmailOpen(false)}>
              Cancelar
            </Button>
            <Button
              type="submit"
              form="form-change-email"
              loading={requestEmailChange.isPending}
              disabled={!newEmail.trim() || !emailPassword}
            >
              Confirmar cambio
            </Button>
          </>
        }
      >
        <form id="form-change-email" onSubmit={submitEmailChange} className="space-y-4">
          <p className="text-xs text-ink-2">
            Ingresa tu nueva dirección de correo y tu contraseña actual. Si el servicio de correo está configurado, recibirás un enlace de confirmación en la nueva dirección.
          </p>

          <div>
            <Label htmlFor="new-email">Nuevo correo electrónico</Label>
            <Input
              id="new-email"
              type="email"
              required
              placeholder="nuevo@empresa.com"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
            />
          </div>

          <div>
            <PasswordField
              id="confirm-pw"
              label="Contraseña actual"
              value={emailPassword}
              onChange={setEmailPassword}
              autoComplete="current-password"
              showRules={false}
            />
          </div>

          {modalNotice && <Alert kind={modalNotice.kind}>{modalNotice.text}</Alert>}
        </form>
      </Modal>
    </>
  );
}
