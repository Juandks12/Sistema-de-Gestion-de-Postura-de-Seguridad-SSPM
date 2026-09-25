import { CheckCircle2 } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';
import { GRADE_LABEL, SCAN_STATUS_LABEL, SEVERITY_LABEL, STATUS_LABEL } from '@/lib/format';
import type { FindingStatus, Grade, ScanStatus, Severity } from '@/lib/types';
import { GRADE_STYLE, SEVERITY_STYLE } from './styles';

export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  const s = SEVERITY_STYLE[severity];
  const Icon = s.icon;
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold', s.chip)}>
      <Icon className="size-3.5" aria-hidden />
      {compact ? null : SEVERITY_LABEL[severity]}
      {compact ? <span className="sr-only">{SEVERITY_LABEL[severity]}</span> : null}
    </span>
  );
}

const findingStatusStyle: Record<FindingStatus, string> = {
  OPEN: 'bg-critical/10 text-critical',
  RESOLVED: 'bg-good/12 text-good-text',
  ACCEPTED: 'bg-accent/12 text-accent-strong',
  FALSE_POSITIVE: 'bg-surface-2 text-ink-2',
};

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium', findingStatusStyle[status])}>
      {STATUS_LABEL[status]}
    </span>
  );
}

const scanStatusStyle: Record<ScanStatus, { chip: string; pulse?: boolean }> = {
  PENDING: { chip: 'bg-surface-2 text-ink-2' },
  RUNNING: { chip: 'bg-accent/12 text-accent-strong', pulse: true },
  COMPLETED: { chip: 'bg-good/12 text-good-text' },
  FAILED: { chip: 'bg-critical/10 text-critical' },
  CANCELLED: { chip: 'bg-surface-2 text-muted' },
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const s = scanStatusStyle[status];
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium', s.chip)}>
      {s.pulse ? <span className="size-1.5 animate-pulse rounded-full bg-current" aria-hidden /> : null}
      {SCAN_STATUS_LABEL[status]}
    </span>
  );
}

export function GradeBadge({ grade, size = 'md' }: { grade: Grade | null; size?: 'sm' | 'md' }) {
  if (!grade) {
    return (
      <span className={cn('inline-flex items-center justify-center rounded-md bg-surface-2 font-semibold text-muted', size === 'sm' ? 'h-6 min-w-6 px-1.5 text-xs' : 'h-8 min-w-8 px-2 text-sm')} title="Sin evaluar">
        —
      </span>
    );
  }
  const g = GRADE_STYLE[grade];
  return (
    <span
      title={GRADE_LABEL[grade]}
      className={cn('inline-flex items-center justify-center rounded-md font-bold text-white', g.bg, size === 'sm' ? 'h-6 min-w-6 px-1.5 text-xs' : 'h-8 min-w-8 px-2 text-sm')}
    >
      {grade}
    </span>
  );
}

export function Pill({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('inline-flex items-center gap-1 rounded-full border border-border px-2 py-0.5 text-xs text-ink-2', className)}>{children}</span>;
}

export function GoodIcon() {
  return <CheckCircle2 className="size-4 text-good" aria-hidden />;
}
