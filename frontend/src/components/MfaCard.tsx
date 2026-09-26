import { Check, Copy, Download, KeyRound, ShieldCheck, ShieldOff } from 'lucide-react';
import { toDataURL } from 'qrcode';
import { useEffect, useState } from 'react';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Card, CardBody, CardHeader } from '@/components/ui/Card';
import { Input, Label } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { Skeleton } from '@/components/ui/Spinner';
import { useMfaDisable, useMfaEnable, useMfaSetup, useMfaStatus } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { timeAgo } from '@/lib/format';
import type { MfaSetup } from '@/lib/types';

function QrImage({ url }: { url: string }) {
  const [src, setSrc] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    toDataURL(url, { width: 220, margin: 1 }).then((data) => !cancelled && setSrc(data));
    return () => {
      cancelled = true;
    };
  }, [url]);
  if (!src) return <Skeleton className="mx-auto size-[220px]" />;
  return <img src={src} alt="Código QR para la aplicación de autenticación" className="mx-auto rounded-lg border border-border bg-white p-1" />;
}

function RecoveryCodes({ codes }: { codes: string[] }) {
  const [copied, setCopied] = useState(false);
  const text = codes.join('\n');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  const download = () => {
    const blob = new Blob([`Códigos de recuperación de SSPM (un solo uso cada uno)\n\n${text}\n`], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'sspm-codigos-de-recuperacion.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <div>
      <ul className="tabular grid grid-cols-2 gap-x-6 gap-y-1 rounded-lg border border-border bg-surface-2/60 p-4 font-mono text-sm text-ink">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="mt-3 flex gap-2">
        <Button size="sm" variant="secondary" icon={copied ? <Check className="size-4 text-good" /> : <Copy className="size-4" />} onClick={copy}>
          Copiar
        </Button>
        <Button size="sm" variant="secondary" icon={<Download className="size-4" />} onClick={download}>
          Descargar
        </Button>
      </div>
    </div>
  );
}

/** Gestión de la verificación en dos pasos (TOTP) del propio usuario. */
export function MfaCard() {
  const status = useMfaStatus();
  const setupMutation = useMfaSetup();
  const enable = useMfaEnable();
  const disable = useMfaDisable();
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [disabling, setDisabling] = useState(false);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const startSetup = async () => {
    setError(null);
    try {
      setSetup(await setupMutation.mutateAsync());
      setCode('');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo iniciar la configuración.');
    }
  };

  const confirm = async () => {
    setError(null);
    try {
      const res = await enable.mutateAsync(code.trim());
      setRecoveryCodes(res.recoveryCodes);
      setSetup(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo activar la verificación.');
    }
  };

  const doDisable = async () => {
    setError(null);
    try {
      await disable.mutateAsync({ password, code: code.trim() });
      setDisabling(false);
      setPassword('');
      setCode('');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo desactivar la verificación.');
    }
  };

  if (status.isPending) return <Skeleton className="h-40" />;
  const enabled = status.data?.enabled ?? false;

  return (
    <Card>
      <CardHeader
        title="Verificación en dos pasos"
        subtitle="Además de la contraseña, un código de tu aplicación de autenticación (Google Authenticator, Microsoft Authenticator, 1Password...)."
      />
      <CardBody>
        {enabled ? (
          <div className="space-y-3">
            <p className="flex items-center gap-2 text-sm text-ink">
              <ShieldCheck className="size-5 shrink-0 text-good" aria-hidden />
              <span>
                <span className="font-medium">Activada</span> {timeAgo(status.data!.enabledAt)} · te quedan{' '}
                {status.data!.recoveryCodesLeft} código(s) de recuperación
              </span>
            </p>
            {status.data!.recoveryCodesLeft <= 2 ? (
              <Alert kind="info">
                Te quedan pocos códigos de recuperación. Si los agotas y pierdes el dispositivo, un administrador tendrá que desactivarte la verificación.
              </Alert>
            ) : null}
            {recoveryCodes ? (
              <div>
                <p className="mb-2 text-sm text-ink-2">
                  Guarda estos códigos en un lugar seguro: cada uno entra <span className="font-medium text-ink">una sola vez</span> si pierdes el dispositivo. No volverán a mostrarse.
                </p>
                <RecoveryCodes codes={recoveryCodes} />
              </div>
            ) : null}
            <Button variant="secondary" icon={<ShieldOff className="size-4" />} onClick={() => { setDisabling(true); setCode(''); setError(null); }}>
              Desactivar
            </Button>
          </div>
        ) : setup ? (
          <div className="grid gap-4 sm:grid-cols-[auto_1fr]">
            <QrImage url={setup.otpauthUrl} />
            <div className="min-w-0 space-y-3">
              <ol className="list-decimal space-y-1 pl-5 text-sm text-ink-2">
                <li>Abre tu aplicación de autenticación y escanea el código QR.</li>
                <li>
                  Si no puedes escanearlo, añade la clave manualmente:{' '}
                  <code className="[overflow-wrap:anywhere] rounded bg-surface-2 px-1 py-0.5 text-xs text-ink">{setup.secret}</code>
                </li>
                <li>Escribe el código de 6 dígitos que muestra la aplicación.</li>
              </ol>
              <div className="max-w-[12rem]">
                <Label htmlFor="mfa-first-code">Código</Label>
                <Input id="mfa-first-code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" className="tabular tracking-widest" />
              </div>
              {error ? <Alert kind="error">{error}</Alert> : null}
              <div className="flex gap-2">
                <Button onClick={confirm} loading={enable.isPending} disabled={code.trim().length < 6}>Activar</Button>
                <Button variant="secondary" onClick={() => setSetup(null)}>Cancelar</Button>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-ink-2">
              Recomendada para todas las cuentas, especialmente las de administrador: aunque roben tu contraseña, no podrán entrar sin tu dispositivo.
            </p>
            {error ? <Alert kind="error">{error}</Alert> : null}
            <Button icon={<KeyRound className="size-4" />} onClick={startSetup} loading={setupMutation.isPending}>
              Activar la verificación en dos pasos
            </Button>
          </div>
        )}
      </CardBody>

      <Modal
        open={disabling}
        onClose={() => setDisabling(false)}
        title="Desactivar la verificación en dos pasos"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDisabling(false)}>Cancelar</Button>
            <Button onClick={doDisable} loading={disable.isPending} disabled={password.length === 0 || code.trim().length < 6}>
              Desactivar
            </Button>
          </>
        }
      >
        <p className="text-sm text-ink-2">Tu cuenta volverá a protegerse solo con la contraseña.</p>
        <div className="mt-4 space-y-3">
          <div>
            <Label htmlFor="mfa-dis-pw">Tu contraseña</Label>
            <Input id="mfa-dis-pw" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="mfa-dis-code">Código de la aplicación</Label>
            <Input id="mfa-dis-code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" className="tabular tracking-widest" />
          </div>
          {error ? <Alert kind="error">{error}</Alert> : null}
        </div>
      </Modal>
    </Card>
  );
}
