import { KeyRound, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Input, Label } from '@/components/ui/Field';
import { ApiError } from '@/lib/api';

export function LoginPage() {
  const { user, login, loginMfa } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  /** Token intermedio cuando la cuenta exige el segundo paso (código TOTP). */
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState('');

  if (user) return <Navigate to="/" replace />;

  const goBack = () => {
    const from = (location.state as { from?: string } | null)?.from ?? '/';
    navigate(from, { replace: true });
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const challenge = await login(email, password);
      if (challenge) {
        setMfaToken(challenge.mfaToken);
        setCode('');
        return;
      }
      goBack();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 401
          ? 'Correo o contraseña incorrectos.'
          : err instanceof ApiError && err.status === 429
            ? err.message
            : 'No se pudo iniciar sesión. Comprueba que la API esté disponible.',
      );
    } finally {
      setLoading(false);
    }
  };

  const onSubmitMfa = async (e: FormEvent) => {
    e.preventDefault();
    if (!mfaToken) return;
    setError(null);
    setLoading(true);
    try {
      await loginMfa(mfaToken, code.trim());
      goBack();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && /caducó|caduco/i.test(err.message)) {
        setMfaToken(null);
        setError(err.message);
      } else {
        setError(err instanceof ApiError ? err.message : 'No se pudo comprobar el código.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid min-h-screen bg-bg lg:grid-cols-2">
      <div className="hidden flex-col justify-between bg-sidebar p-10 text-sidebar-ink lg:flex">
        <div className="flex items-center gap-3">
          <span className="flex size-10 items-center justify-center rounded-lg bg-accent text-white">
            <ShieldCheck className="size-6" aria-hidden />
          </span>
          <span className="text-lg font-semibold">SSPM · SaaS Lite</span>
        </div>
        <div className="max-w-md">
          <h2 className="text-3xl font-semibold leading-tight">Visibilidad clara de tu superficie de ataque.</h2>
          <p className="mt-4 text-sidebar-muted">
            Inventario de activos, escaneo de puertos y servicios, auditoría web y un Security Score que traduce los hallazgos técnicos en decisiones de negocio.
          </p>
        </div>
        <p className="text-xs text-sidebar-muted">Sistema de Gestión de Postura de Seguridad para PyMEs</p>
      </div>

      <div className="flex items-center justify-center p-6 sm:p-10">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <span className="flex size-10 items-center justify-center rounded-lg bg-accent text-white">
              <ShieldCheck className="size-6" aria-hidden />
            </span>
            <span className="text-lg font-semibold text-ink">SSPM</span>
          </div>
          {mfaToken ? (
            <>
              <h1 className="flex items-center gap-2 text-2xl font-semibold text-ink">
                <KeyRound className="size-6 text-accent" aria-hidden /> Verificación en dos pasos
              </h1>
              <p className="mt-1 text-sm text-ink-2">
                Escribe el código de 6 dígitos de tu aplicación de autenticación, o un código de recuperación.
              </p>
              <form onSubmit={onSubmitMfa} className="mt-6 space-y-4">
                <div>
                  <Label htmlFor="mfa-code">Código</Label>
                  <Input
                    id="mfa-code"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    autoFocus
                    required
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder="123456"
                    className="tabular text-lg tracking-widest"
                  />
                </div>
                {error ? <Alert kind="error">{error}</Alert> : null}
                <Button type="submit" loading={loading} className="w-full">Verificar</Button>
                <button
                  type="button"
                  onClick={() => { setMfaToken(null); setError(null); }}
                  className="w-full text-center text-sm font-medium text-accent hover:underline"
                >
                  Volver a empezar
                </button>
              </form>
            </>
          ) : (
            <>
              <h1 className="text-2xl font-semibold text-ink">Iniciar sesión</h1>
              <p className="mt-1 text-sm text-ink-2">Accede con la cuenta de tu organización.</p>

              <form onSubmit={onSubmit} className="mt-6 space-y-4">
                <div>
                  <Label htmlFor="email">Correo electrónico</Label>
                  <Input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="tu@empresa.com" />
                </div>
                <div>
                  <div className="flex items-end justify-between gap-2">
                    <Label htmlFor="password">Contraseña</Label>
                    <Link to="/forgot-password" className="mb-1.5 text-xs font-medium text-accent hover:underline">
                      ¿La olvidaste?
                    </Link>
                  </div>
                  <Input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
                {error ? <Alert kind="error">{error}</Alert> : null}
                <Button type="submit" loading={loading} className="w-full">
                  Entrar
                </Button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
