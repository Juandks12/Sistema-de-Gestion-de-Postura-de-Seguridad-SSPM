import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

export function StatTile({ label, value, hint, icon: Icon, tone = 'default' }: { label: string; value: ReactNode; hint?: ReactNode; icon?: LucideIcon; tone?: 'default' | 'critical' | 'accent' }) {
  return (
    <div className="rounded-card border border-border bg-surface p-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-ink-2">{label}</p>
        {Icon ? <Icon className={cn('size-4', tone === 'critical' ? 'text-critical' : tone === 'accent' ? 'text-accent' : 'text-muted')} aria-hidden /> : null}
      </div>
      <p className={cn('mt-2 text-2xl font-semibold', tone === 'critical' ? 'text-critical' : 'text-ink')}>{value}</p>
      {hint ? <p className="mt-1 text-xs text-muted">{hint}</p> : null}
    </div>
  );
}
