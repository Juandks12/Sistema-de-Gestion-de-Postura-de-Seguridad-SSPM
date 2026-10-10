import { ArrowRight, CheckCircle2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/Spinner';
import { useConfirmEmailChange, useVerifyEmail } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { AuthLayout } from './AuthLayout';

export function VerifyEmailPage() {
  const [params] = useSearchParams();
  const token = params.get('token')?.trim() ?? '';
  const type = params.get('type')?.trim(); // 'change' o undefined
  const isEmailChange = type === 'change';

  const { user, applySession, refreshUser } = useAuth();
  const verifyEmail = useVerifyEmail();
  const confirmEmailChange = useConfirmEmailChange();

  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>(() => (!token ? 'error' : 'idle'));
  const [message, setMessage] = useState<string>(() =>
    !token ? 'El enlace no contiene un token de verificación válido. Revisa el correo recibido.' : '',
  );
  const executedRef = useRef(false);

  useEffect(() => {
    if (!token) return;

    if (executedRef.current) return;
    executedRef.current = true;

    // Trigger verification asynchronously
    const runVerification = async () => {
      setStatus('loading');
      if (isEmailChange) {
        try {
          const res = await confirmEmailChange.mutateAsync(token);
          applySession(res);
          setStatus('success');
          setMessage(`Tu correo electrónico ha sido actualizado correctamente a ${res.user.email}.`);
        } catch (err) {
          setStatus('error');
          setMessage(err instanceof ApiError ? err.message : 'No se pudo confirmar el cambio de correo electrónico.');
        }
      } else {
        try {
          const res = await verifyEmail.mutateAsync(token);
          setStatus('success');
          setMessage(res.message || 'Tu correo electrónico ha sido verificado satisfactoriamente.');
          if (user) {
            await refreshUser();
          }
        } catch (err) {
          setStatus('error');
          setMessage(err instanceof ApiError ? err.message : 'No se pudo verificar el correo electrónico.');
        }
      }
    };

    void runVerification();
  }, [token, isEmailChange, applySession, confirmEmailChange, refreshUser, user, verifyEmail]);

  const pageTitle = isEmailChange ? 'Confirmación de cambio de correo' : 'Verificación de correo';
  const pageSubtitle = isEmailChange
    ? 'Estamos validando la actualización de tu dirección de correo electrónico.'
    : 'Estamos validando tu dirección de correo electrónico.';

  return (
    <AuthLayout title={pageTitle} subtitle={pageSubtitle}>
      <div className="space-y-5">
        {status === 'loading' && (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <Spinner className="size-8 text-accent" />
            <p className="mt-3 text-sm font-medium text-ink-2">Verificando token de seguridad...</p>
          </div>
        )}

        {status === 'success' && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-4 text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 className="size-6 shrink-0" />
              <div className="min-w-0">
                <p className="font-semibold">{isEmailChange ? 'Cambio confirmado' : 'Correo verificado'}</p>
                <p className="mt-0.5 text-sm">{message}</p>
              </div>
            </div>

            <div className="pt-2">
              <Link to={user ? '/account' : '/login'}>
                <Button className="w-full" icon={<ArrowRight className="size-4" />}>
                  {user ? 'Volver a mi cuenta' : 'Iniciar sesión'}
                </Button>
              </Link>
            </div>
          </div>
        )}

        {status === 'error' && (
          <div className="space-y-4">
            <Alert kind="error">{message}</Alert>

            <div className="pt-2 flex flex-col gap-2">
              <Link to={user ? '/account' : '/login'}>
                <Button variant="secondary" className="w-full">
                  {user ? 'Volver a mi cuenta' : 'Ir a iniciar sesión'}
                </Button>
              </Link>
            </div>
          </div>
        )}
      </div>
    </AuthLayout>
  );
}
