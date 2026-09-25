import { Activity, LayoutDashboard, LogOut, Menu, Radar, Server, ShieldAlert, ShieldCheck, Users, X } from 'lucide-react';
import { useState } from 'react';
import { Link, NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { cn } from '@/lib/cn';

const nav = [
  { to: '/', label: 'Vista general', icon: LayoutDashboard, end: true, adminOnly: false },
  { to: '/assets', label: 'Activos', icon: Server, adminOnly: false },
  { to: '/findings', label: 'Hallazgos', icon: ShieldAlert, adminOnly: false },
  { to: '/scans', label: 'Escaneos', icon: Radar, adminOnly: false },
  { to: '/users', label: 'Usuarios', icon: Users, adminOnly: true },
];

const roleLabel = { ADMIN: 'Administrador', ANALYST: 'Analista', VIEWER: 'Gerencia' } as const;

export function AppShell() {
  const { user, logout, hasRole } = useAuth();
  const [open, setOpen] = useState(false);

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 px-5 py-5">
        <span className="flex size-9 items-center justify-center rounded-lg bg-accent text-white">
          <ShieldCheck className="size-5" aria-hidden />
        </span>
        <div className="leading-tight">
          <p className="text-[15px] font-semibold text-sidebar-ink">SSPM</p>
          <p className="text-xs text-sidebar-muted">Postura de seguridad</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 px-3" aria-label="Principal">
        {nav.filter((item) => !item.adminOnly || hasRole('ADMIN')).map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={() => setOpen(false)}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                isActive ? 'bg-white/10 text-sidebar-ink' : 'text-sidebar-muted hover:bg-white/5 hover:text-sidebar-ink',
              )
            }
          >
            <Icon className="size-[18px]" aria-hidden />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-sidebar-line px-4 py-4">
        <div className="flex items-center gap-2">
          <Link to="/account" onClick={() => setOpen(false)} title="Mi cuenta" className="-m-1 flex min-w-0 flex-1 items-center gap-3 rounded-lg p-1 hover:bg-white/5">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-white/10 text-sm font-semibold text-sidebar-ink" aria-hidden>
              {user?.fullName?.slice(0, 1).toUpperCase()}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium text-sidebar-ink">{user?.fullName}</span>
              <span className="block truncate text-xs text-sidebar-muted">{user ? roleLabel[user.role] : ''} · Mi cuenta</span>
            </span>
          </Link>
          <button type="button" onClick={logout} title="Cerrar sesión" aria-label="Cerrar sesión" className="rounded-md p-1.5 text-sidebar-muted hover:bg-white/10 hover:text-sidebar-ink">
            <LogOut className="size-4" />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-bg lg:flex">
      {/* Barra lateral fija en escritorio */}
      <aside className="hidden w-64 shrink-0 bg-sidebar lg:fixed lg:inset-y-0 lg:block">{sidebar}</aside>

      {/* Cajón en móvil */}
      {open ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/50" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 max-w-[85vw] bg-sidebar shadow-2xl">
            <button type="button" onClick={() => setOpen(false)} aria-label="Cerrar menú" className="absolute top-4 right-3 rounded-md p-1.5 text-sidebar-muted hover:text-sidebar-ink">
              <X className="size-5" />
            </button>
            {sidebar}
          </aside>
        </div>
      ) : null}

      <div className="flex min-h-screen flex-1 flex-col lg:pl-64">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-surface/90 px-4 backdrop-blur lg:hidden">
          <button type="button" onClick={() => setOpen(true)} aria-label="Abrir menú" className="rounded-md p-1.5 text-ink-2 hover:bg-surface-2">
            <Menu className="size-5" />
          </button>
          <span className="flex items-center gap-2 font-semibold text-ink">
            <ShieldCheck className="size-5 text-accent" aria-hidden /> SSPM
          </span>
          <Activity className="ml-auto size-4 text-muted" aria-hidden />
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
