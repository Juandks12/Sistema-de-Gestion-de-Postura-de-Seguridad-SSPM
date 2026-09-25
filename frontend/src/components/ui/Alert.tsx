import { AlertTriangle, CheckCircle2, Info } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

const styles = {
  error: { cls: 'border-critical/30 bg-critical/8 text-critical', Icon: AlertTriangle },
  success: { cls: 'border-good/30 bg-good/8 text-good-text', Icon: CheckCircle2 },
  info: { cls: 'border-accent/30 bg-accent/8 text-accent-strong', Icon: Info },
};

export function Alert({ kind = 'info', children, className }: { kind?: keyof typeof styles; children: ReactNode; className?: string }) {
  const { cls, Icon } = styles[kind];
  return (
    <div role={kind === 'error' ? 'alert' : 'status'} className={cn('flex items-start gap-2 rounded-lg border px-3 py-2 text-sm', cls, className)}>
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="min-w-0">{children}</div>
    </div>
  );
}
