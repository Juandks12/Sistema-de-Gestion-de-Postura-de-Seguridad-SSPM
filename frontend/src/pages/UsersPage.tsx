import { KeyRound, MoreHorizontal, Plus, UserCheck, UserX, Users } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input, Label, Select } from '@/components/ui/Field';
import { Modal } from '@/components/ui/Modal';
import { PageHeader } from '@/components/ui/PageHeader';
import { PasswordField } from '@/components/ui/PasswordField';
import { Skeleton } from '@/components/ui/Spinner';
import { Table, Td, Th } from '@/components/ui/Table';
import { useCreateUser, useResetUserPassword, useUpdateUser, useUsers } from '@/hooks/queries';
import { ApiError } from '@/lib/api';
import { cn } from '@/lib/cn';
import { ROLE_DESCRIPTION, ROLE_LABEL, formatDateTime, timeAgo } from '@/lib/format';
import { isStrongPassword } from '@/lib/password';
import type { OrgUser, UserRole } from '@/lib/types';

const ROLES: UserRole[] = ['ADMIN', 'ANALYST', 'VIEWER'];

const roleChip: Record<UserRole, string> = {
  ADMIN: 'bg-accent/12 text-accent-strong',
  ANALYST: 'bg-surface-2 text-ink',
  VIEWER: 'bg-surface-2 text-ink-2',
};

type Notice = { kind: 'success' | 'error'; text: string } | null;

export function UsersPage() {
  const { user, hasRole } = useAuth();
  const isAdmin = hasRole('ADMIN');
  const users = useUsers(isAdmin);
  const update = useUpdateUser();
  const [createOpen, setCreateOpen] = useState(false);
  const [resetFor, setResetFor] = useState<OrgUser | null>(null);
  const [notice, setNotice] = useState<Notice>(null);

  if (!isAdmin) return <Navigate to="/" replace />;

  const run = async (label: string, fn: () => Promise<unknown>) => {
    setNotice(null);
    try {
      await fn();
      setNotice({ kind: 'success', text: label });
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof ApiError ? err.message : 'No se pudo completar la acción.' });
    }
  };

  const list = users.data ?? [];
  const active = list.filter((u) => u.isActive).length;

  return (
    <>
      <PageHeader
        title="Usuarios"
        description={users.data ? `${active} activos de ${list.length} en tu organización.` : 'Personas con acceso a tu organización.'}
        actions={<Button icon={<Plus className="size-4" />} onClick={() => setCreateOpen(true)}>Nuevo usuario</Button>}
      />
      {notice ? <Alert kind={notice.kind} className="mb-4">{notice.text}</Alert> : null}

      <Card>
        {users.isPending ? (
          <div className="space-y-3 p-5">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : list.length === 0 ? (
          <EmptyState icon={Users} title="Sin usuarios" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Usuario</Th>
                <Th>Rol</Th>
                <Th className="hidden md:table-cell">Estado</Th>
                <Th className="hidden lg:table-cell">Último acceso</Th>
                <Th className="w-1" />
              </tr>
            </thead>
            <tbody>
              {list.map((u) => {
                const isSelf = u.id === user?.id;
                return (
                  <tr key={u.id} className={cn('hover:bg-surface-2/60', !u.isActive && 'opacity-60')}>
                    <Td>
                      <div className="flex items-center gap-3">
                        <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-surface-2 text-sm font-semibold text-ink-2" aria-hidden>
                          {u.fullName.slice(0, 1).toUpperCase()}
                        </span>
                        <div className="min-w-0">
                          <p className="truncate font-medium text-ink">
                            {u.fullName}
                            {isSelf ? <span className="ml-2 rounded bg-surface-2 px-1.5 py-0.5 text-[11px] font-medium text-muted">Tú</span> : null}
                          </p>
                          <p className="truncate text-xs text-muted">{u.email}</p>
                        </div>
                      </div>
                    </Td>
                    <Td>
                      {isSelf ? (
                        <span className={cn('inline-flex rounded-md px-2 py-0.5 text-xs font-medium', roleChip[u.role])}>{ROLE_LABEL[u.role]}</span>
                      ) : (
                        <Select
                          aria-label={`Rol de ${u.fullName}`}
                          value={u.role}
                          disabled={update.isPending}
                          onChange={(e) => {
                            const role = e.target.value as UserRole;
                            void run(`${u.fullName} ahora es ${ROLE_LABEL[role].toLowerCase()}.`, () => update.mutateAsync({ id: u.id, role }));
                          }}
                          className="h-8 w-auto min-w-36 text-[13px]"
                        >
                          {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                        </Select>
                      )}
                    </Td>
                    <Td className="hidden md:table-cell">
                      <span className={cn('inline-flex items-center gap-1.5 text-sm', u.isActive ? 'text-good-text' : 'text-muted')}>
                        <span className={cn('size-2 rounded-full', u.isActive ? 'bg-good' : 'bg-muted')} aria-hidden />
                        {u.isActive ? 'Activo' : 'Desactivado'}
                      </span>
                    </Td>
                    <Td className="hidden whitespace-nowrap text-ink-2 lg:table-cell" title={formatDateTime(u.lastLoginAt)}>
                      {u.lastLoginAt ? timeAgo(u.lastLoginAt) : <span className="text-muted">Nunca</span>}
                    </Td>
                    <Td className="text-right">
                      {isSelf ? null : (
                        <RowMenu
                          user={u}
                          onReset={() => setResetFor(u)}
                          onToggle={() =>
                            run(u.isActive ? `${u.fullName} ya no puede acceder.` : `${u.fullName} puede volver a acceder.`, () =>
                              update.mutateAsync({ id: u.id, isActive: !u.isActive }),
                            )
                          }
                        />
                      )}
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Card>

      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
        {ROLES.map((r) => (
          <div key={r} className="rounded-card border border-border bg-surface p-4">
            <p className="text-sm font-semibold text-ink">{ROLE_LABEL[r]}</p>
            <p className="mt-1 text-sm text-ink-2">{ROLE_DESCRIPTION[r]}</p>
          </div>
        ))}
      </div>

      {createOpen ? <CreateUserModal onClose={() => setCreateOpen(false)} onCreated={(u) => setNotice({ kind: 'success', text: `Usuario ${u.fullName} creado. Comunícale su contraseña por un canal seguro.` })} /> : null}
      {resetFor ? <ResetPasswordModal user={resetFor} onClose={() => setResetFor(null)} onDone={() => setNotice({ kind: 'success', text: `Contraseña de ${resetFor.fullName} restablecida. Sus sesiones abiertas se han cerrado.` })} /> : null}
    </>
  );
}

const MENU_WIDTH = 224;
const MENU_HEIGHT = 96;

/**
 * Menú de acciones por fila. Se posiciona con `position: fixed` a partir del botón
 * para que el contenedor con desplazamiento de la tabla no lo recorte, y se abre
 * hacia arriba cuando no cabe debajo.
 */
function RowMenu({ user, onReset, onToggle }: { user: OrgUser; onReset: () => void; onToggle: () => void }) {
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const open = pos !== null;

  const toggle = () => {
    if (open) {
      setPos(null);
      return;
    }
    const r = buttonRef.current?.getBoundingClientRect();
    if (!r) return;
    const below = r.bottom + 4;
    const top = below + MENU_HEIGHT > window.innerHeight ? r.top - MENU_HEIGHT - 4 : below;
    const left = Math.max(8, Math.min(r.right - MENU_WIDTH, window.innerWidth - MENU_WIDTH - 8));
    setPos({ top, left });
  };

  useEffect(() => {
    if (!open) return;
    const close = () => setPos(null);
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!menuRef.current?.contains(t) && !buttonRef.current?.contains(t)) close();
    };
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close();
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', close, true);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', close, true);
    };
  }, [open]);

  return (
    <>
      <button ref={buttonRef} type="button" aria-haspopup="menu" aria-expanded={open} aria-label={`Acciones para ${user.fullName}`} onClick={toggle} className="rounded-md p-1.5 text-muted hover:bg-surface-2 hover:text-ink">
        <MoreHorizontal className="size-5" />
      </button>
      {pos ? (
        <div ref={menuRef} role="menu" style={{ position: 'fixed', top: pos.top, left: pos.left, width: MENU_WIDTH }} className="z-50 overflow-hidden rounded-lg border border-border bg-surface py-1 text-left shadow-lg">
          <button type="button" role="menuitem" onClick={() => { setPos(null); onReset(); }} className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-ink hover:bg-surface-2">
            <KeyRound className="size-4 text-muted" aria-hidden /> Restablecer contraseña
          </button>
          <button type="button" role="menuitem" onClick={() => { setPos(null); onToggle(); }} className={cn('flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-surface-2', user.isActive ? 'text-critical' : 'text-ink')}>
            {user.isActive ? <UserX className="size-4" aria-hidden /> : <UserCheck className="size-4 text-muted" aria-hidden />}
            {user.isActive ? 'Desactivar acceso' : 'Reactivar acceso'}
          </button>
        </div>
      ) : null}
    </>
  );
}

function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: (u: OrgUser) => void }) {
  const create = useCreateUser();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<UserRole>('ANALYST');
  const [error, setError] = useState<string | null>(null);

  const valid = fullName.trim().length >= 2 && email.includes('@') && isStrongPassword(password);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const u = await create.mutateAsync({ fullName: fullName.trim(), email: email.trim(), password, role });
      onCreated(u);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo crear el usuario.');
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Nuevo usuario"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancelar</Button>
          <Button type="submit" form="create-user" loading={create.isPending} disabled={!valid}>Crear usuario</Button>
        </>
      }
    >
      <form id="create-user" onSubmit={submit} className="space-y-4">
        <div>
          <Label htmlFor="u-name">Nombre completo</Label>
          <Input id="u-name" required autoFocus value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="Carlos Ruiz" />
        </div>
        <div>
          <Label htmlFor="u-email">Correo electrónico</Label>
          <Input id="u-email" type="email" required autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="carlos@empresa.com" />
        </div>
        <div>
          <Label htmlFor="u-role">Rol</Label>
          <Select id="u-role" value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
            {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
          </Select>
          <p className="mt-1 text-xs text-muted">{ROLE_DESCRIPTION[role]}</p>
        </div>
        <PasswordField label="Contraseña inicial" value={password} onChange={setPassword} allowGenerate />
        <p className="text-xs text-muted">Entrégale la contraseña por un canal seguro y pídele que la cambie desde "Mi cuenta" al entrar.</p>
        {error ? <Alert kind="error">{error}</Alert> : null}
      </form>
    </Modal>
  );
}

function ResetPasswordModal({ user, onClose, onDone }: { user: OrgUser; onClose: () => void; onDone: () => void }) {
  const reset = useResetUserPassword();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    try {
      await reset.mutateAsync({ id: user.id, newPassword: password });
      onDone();
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'No se pudo restablecer la contraseña.');
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title="Restablecer contraseña"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancelar</Button>
          <Button onClick={submit} loading={reset.isPending} disabled={!isStrongPassword(password)}>Restablecer</Button>
        </>
      }
    >
      <p className="text-sm text-ink-2">
        Asigna una contraseña nueva a <span className="font-medium text-ink">{user.fullName}</span> ({user.email}). Todas sus sesiones abiertas se cerrarán.
      </p>
      <div className="mt-4">
        <PasswordField label="Nueva contraseña" value={password} onChange={setPassword} allowGenerate />
      </div>
      {error ? <Alert kind="error" className="mt-3">{error}</Alert> : null}
    </Modal>
  );
}
