import { useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { PasswordField } from '@/components/ui/PasswordField';
import { api, ApiError } from '@/lib/api';
import { isStrongPassword } from '@/lib/password';
import type { AuthResponse } from '@/lib/types';
import { AuthLayout } from './AuthLayout';

export function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get('token') ?? '';
  const navigate = useNavigate();
  const { applySession } = useAuth();
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const mismatch = confirm.length > 0 && confirm !== password;
  const valid = token.length > 0 && isStrongPassword(password) && password === confirm;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api<AuthResponse>('/auth/reset-password', { method: 'POST', json: { token, newPassword: password } });
      applySession(res);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo restablecer la contraseña.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout title="Elige una contraseña nueva" subtitle="Al guardarla entrarás directamente y se cerrarán tus otras sesiones.">
      {token ? (
        <form onSubmit={submit} className="space-y-4">
          <PasswordField id="np" label="Nueva contraseña" value={password} onChange={setPassword} allowGenerate />
          <div>
            <PasswordField id="np2" label="Repite la contraseña" value={confirm} onChange={setConfirm} showRules={false} />
            {mismatch ? <p className="mt-1 text-xs text-critical">Las contraseñas no coinciden.</p> : null}
          </div>
          {error ? <Alert kind="error">{error}</Alert> : null}
          <Button type="submit" loading={loading} disabled={!valid} className="w-full">Guardar y entrar</Button>
        </form>
      ) : (
        <div className="space-y-4">
          <Alert kind="error">Falta el token del enlace. Abre el enlace completo del correo.</Alert>
          <Link to="/forgot-password" className="text-sm font-medium text-accent hover:underline">Solicitar un enlace nuevo</Link>
        </div>
      )}
    </AuthLayout>
  );
}
