import { useQuery } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Input, Label } from '@/components/ui/Field';
import { PasswordField } from '@/components/ui/PasswordField';
import { Skeleton } from '@/components/ui/Spinner';
import { api, ApiError } from '@/lib/api';
import { ROLE_LABEL } from '@/lib/format';
import { isStrongPassword } from '@/lib/password';
import type { AuthResponse, InvitationInfo } from '@/lib/types';
import { AuthLayout } from './AuthLayout';

export function InvitationPage() {
  const [params] = useSearchParams();
  const token = params.get('token') ?? '';
  const navigate = useNavigate();
  const { applySession } = useAuth();
  const info = useQuery({
    queryKey: ['invitation-info', token],
    queryFn: () => api<InvitationInfo>(`/auth/invitations/info?token=${encodeURIComponent(token)}`),
    enabled: token.length > 0,
    retry: false,
  });
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const valid = fullName.trim().length >= 2 && isStrongPassword(password);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api<AuthResponse>('/auth/invitations/accept', {
        method: 'POST',
        json: { token, fullName: fullName.trim(), password },
      });
      applySession(res);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo aceptar la invitación.');
    } finally {
      setLoading(false);
    }
  };

  if (!token || info.isError) {
    return (
      <AuthLayout title="Invitación no disponible">
        <div className="space-y-4">
          <Alert kind="error">
            {info.error instanceof ApiError ? info.error.message : 'La invitación no es válida o ya caducó. Pide que te la reenvíen.'}
          </Alert>
          <Link to="/login" className="text-sm font-medium text-accent hover:underline">Ir a iniciar sesión</Link>
        </div>
      </AuthLayout>
    );
  }
  if (info.isPending) {
    return (
      <AuthLayout title="Invitación">
        <Skeleton className="h-40" />
      </AuthLayout>
    );
  }

  const data = info.data;
  return (
    <AuthLayout
      title={`Únete a ${data.organizationName}`}
      subtitle={
        <>
          Crearás tu cuenta <span className="font-medium text-ink">{data.email}</span> con el rol de {ROLE_LABEL[data.role].toLowerCase()}.
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4">
        <div>
          <Label htmlFor="fullName">Tu nombre</Label>
          <Input id="fullName" autoComplete="name" required value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="Nombre y apellido" />
        </div>
        <PasswordField id="invite-pw" label="Contraseña" value={password} onChange={setPassword} allowGenerate />
        {error ? <Alert kind="error">{error}</Alert> : null}
        <Button type="submit" loading={loading} disabled={!valid} className="w-full">Crear mi cuenta</Button>
      </form>
    </AuthLayout>
  );
}
