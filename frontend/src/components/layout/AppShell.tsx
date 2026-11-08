import {
  Activity,
  BellRing,
  ClipboardCheck,
  Cloud,
  FileText,
  FlaskConical,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Users,
  X,
} from 'lucide-react';
import type { ComponentType } from 'react';
import { useState } from 'react';
import { Link, NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { useAlertsSummary, useFindingsSummary, useThreatLabSummary } from '@/hooks/queries';
import { cn } from '@/lib/cn';

interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string; 'aria-hidden'?: boolean }>;
  end?: boolean;
  adminOnly: boolean;
  badge?: 'alerts' | 'findings' | 'threat-lab';
}

interface NavDomainSection {
  id: string;
  title: string;
  items: NavItem[];
}

const navSections: NavDomainSection[] = [
  {
    id: 'executive',
    title: '1. Comando Ejecutivo',
    items: [
      { to: '/', label: 'Vista General 360°', icon: LayoutDashboard, end: true, adminOnly: false },
    ],
  },
  {
    id: 'surface',
    title: '2. Superficie y Diagnóstico',
    items: [
      { to: '/assets', label: 'Activos y Superficie', icon: Server, adminOnly: false },
      { to: '/scans', label: 'Diagnóstico 360° y Escaneos', icon: Radar, adminOnly: false },
      { to: '/cloud', label: 'Seguridad Cloud (CSPM)', icon: Cloud, adminOnly: false },
    ],
  },
  {
    id: 'threat-lab',
    title: '3. Laboratorio de Amenazas',
    items: [
      {
        to: '/threat-lab',
        label: 'Malware y Phishing Lab',
        icon: FlaskConical,
        adminOnly: false,
        badge: 'threat-lab',
      },
    ],
  },
  {
    id: 'grc-hub',
    title: '4. Hallazgos y Gobierno GRC',
    items: [
      {
        to: '/findings',
        label: 'Centro de Hallazgos',
        icon: ShieldAlert,
        adminOnly: false,
        badge: 'findings',
      },
      { to: '/compliance', label: 'Cumplimiento y Normativa', icon: ClipboardCheck, adminOnly: false },
    ],
  },
  {
    id: 'operations',
    title: '5. Operaciones y Gobierno',
    items: [
      { to: '/alerts', label: 'Alertas Tempranas', icon: BellRing, adminOnly: false, badge: 'alerts' },
      { to: '/reports', label: 'Reportes PDF / GRC', icon: FileText, adminOnly: false },
      { to: '/users', label: 'Usuarios y Accesos', icon: Users, adminOnly: true },
      { to: '/audit', label: 'Auditoría Forense', icon: ScrollText, adminOnly: true },
      { to: '/settings', label: 'Configuración y SIEM', icon: Settings, adminOnly: true },
    ],
  },
];

const roleLabel = { ADMIN: 'Administrador', ANALYST: 'Analista', VIEWER: 'Gerencia' } as const;

export function AppShell() {
  const { user, logout, hasRole } = useAuth();
  const [open, setOpen] = useState(false);
  const alerts = useAlertsSummary();
  const findingsSummary = useFindingsSummary();
  const threatSummary = useThreatLabSummary();

  const pendingAlerts = alerts.data?.unacknowledged ?? 0;
  const openFindingsCount = findingsSummary.data?.total ?? 0;
  const maliciousThreatsCount = threatSummary.data?.byVerdict.MALICIOUS ?? 0;

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 px-5 py-4">
        <span className="flex size-9 items-center justify-center rounded-lg bg-accent text-white">
          <ShieldCheck className="size-5" aria-hidden />
        </span>
        <div className="leading-tight">
          <p className="text-[15px] font-semibold text-sidebar-ink">SSPM 360°</p>
          <p className="text-[11px] text-sidebar-muted">Postura, GRC &amp; Threat Lab</p>
        </div>
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-2" aria-label="Principal">
        {navSections.map((section) => {
          const visibleItems = section.items.filter((item) => !item.adminOnly || hasRole('ADMIN'));
          if (visibleItems.length === 0) return null;

          return (
            <div key={section.id} className="space-y-1">
              <p className="px-2.5 text-[10px] font-bold uppercase tracking-wider text-sidebar-muted/75">
                {section.title}
              </p>
              {visibleItems.map(({ to, label, icon: Icon, end, badge }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  onClick={() => setOpen(false)}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] font-medium transition-colors',
                      isActive
                        ? 'bg-white/10 text-sidebar-ink'
                        : 'text-sidebar-muted hover:bg-white/5 hover:text-sidebar-ink',
                    )
                  }
                >
                  <Icon className="size-4 shrink-0" aria-hidden />
                  <span className="truncate">{label}</span>

                  {badge === 'alerts' && pendingAlerts > 0 ? (
                    <span
                      className="ml-auto rounded-full bg-critical px-1.5 py-0.5 text-[10px] leading-none font-semibold text-white"
                      aria-label={`${pendingAlerts} alertas pendientes`}
                    >
                      {pendingAlerts > 99 ? '99+' : pendingAlerts}
                    </span>
                  ) : null}

                  {badge === 'findings' && openFindingsCount > 0 ? (
                    <span
                      className="ml-auto rounded-full bg-white/10 px-1.5 py-0.5 text-[10px] leading-none font-semibold text-sidebar-ink"
                      aria-label={`${openFindingsCount} hallazgos registrados`}
                    >
                      {openFindingsCount > 999 ? '999+' : openFindingsCount}
                    </span>
                  ) : null}

                  {badge === 'threat-lab' && maliciousThreatsCount > 0 ? (
                    <span
                      className="ml-auto rounded-full bg-critical/80 px-1.5 py-0.5 text-[10px] leading-none font-semibold text-white"
                      aria-label={`${maliciousThreatsCount} artefactos maliciosos detectados`}
                    >
                      {maliciousThreatsCount > 99 ? '99+' : maliciousThreatsCount}
                    </span>
                  ) : null}
                </NavLink>
              ))}
            </div>
          );
        })}
      </nav>

      <div className="border-t border-sidebar-line px-4 py-3.5">
        <div className="flex items-center gap-2">
          <Link
            to="/account"
            onClick={() => setOpen(false)}
            title="Mi cuenta"
            className="-m-1 flex min-w-0 flex-1 items-center gap-3 rounded-lg p-1 hover:bg-white/5"
          >
            <span
              className="flex size-8 shrink-0 items-center justify-center rounded-full bg-white/10 text-xs font-semibold text-sidebar-ink"
              aria-hidden
            >
              {user?.fullName?.slice(0, 1).toUpperCase()}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs font-medium text-sidebar-ink">{user?.fullName}</span>
              <span className="block truncate text-[11px] text-sidebar-muted">
                {user ? roleLabel[user.role] : ''} · Mi cuenta
              </span>
            </span>
          </Link>
          <button
            type="button"
            onClick={logout}
            title="Cerrar sesión"
            aria-label="Cerrar sesión"
            className="rounded-md p-1.5 text-sidebar-muted hover:bg-white/10 hover:text-sidebar-ink"
          >
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
          {pendingAlerts > 0 ? (
            <Link to="/alerts" className="ml-auto inline-flex items-center gap-1 rounded-md px-2 py-1 text-sm font-medium text-critical hover:bg-surface-2" aria-label={`${pendingAlerts} alertas pendientes`}>
              <BellRing className="size-4" aria-hidden /> {pendingAlerts}
            </Link>
          ) : (
            <Activity className="ml-auto size-4 text-muted" aria-hidden />
          )}
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
