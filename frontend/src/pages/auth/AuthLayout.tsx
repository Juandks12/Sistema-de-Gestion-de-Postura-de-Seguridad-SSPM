import { ShieldCheck } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

/** Marco de las pantallas públicas de cuenta (olvido, restablecer, invitación). */
export function AuthLayout({ title, subtitle, children }: { title: string; subtitle?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-bg p-6 sm:p-10">
      <div className="w-full max-w-sm">
        <Link to="/login" className="mb-8 flex items-center gap-3">
          <span className="flex size-10 items-center justify-center rounded-lg bg-accent text-white">
            <ShieldCheck className="size-6" aria-hidden />
          </span>
          <span className="text-lg font-semibold text-ink">SSPM</span>
        </Link>
        <h1 className="text-2xl font-semibold text-ink">{title}</h1>
        {subtitle ? <p className="mt-1 text-sm text-ink-2">{subtitle}</p> : null}
        <div className="mt-6">{children}</div>
      </div>
    </div>
  );
}
