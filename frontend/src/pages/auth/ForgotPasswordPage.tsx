import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Input, Label } from '@/components/ui/Field';
import { api, ApiError } from '@/lib/api';
import { AuthLayout } from './AuthLayout';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api<{ message: string; emailEnabled: boolean }>('/auth/forgot-password', {
        method: 'POST',
        json: { email },
      });
      setSent(res.message);
      setWarning(
        res.emailEnabled
          ? null
          : 'Este servidor no tiene configurado el envío de correo; pide a tu administrador que te asigne una contraseña nueva.',
      );
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo enviar la solicitud. Inténtalo de nuevo.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout
      title="¿Olvidaste tu contraseña?"
      subtitle="Te enviamos un enlace por correo para elegir una nueva. Caduca en 30 minutos."
    >
      {sent ? (
        <div className="space-y-4">
          <Alert kind="success">{sent}</Alert>
          {warning ? <Alert kind="info">{warning}</Alert> : null}
          <Link to="/login" className="text-sm font-medium text-accent hover:underline">Volver a iniciar sesión</Link>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <div>
            <Label htmlFor="email">Correo electrónico</Label>
            <Input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="tu@empresa.com" />
          </div>
          {error ? <Alert kind="error">{error}</Alert> : null}
          <Button type="submit" loading={loading} className="w-full">Enviar enlace</Button>
          <p className="text-center text-sm">
            <Link to="/login" className="font-medium text-accent hover:underline">Volver a iniciar sesión</Link>
          </p>
        </form>
      )}
    </AuthLayout>
  );
}
