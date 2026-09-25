import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

export function EmptyState({ icon: Icon, title, description, action }: { icon: LucideIcon; title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <div className="mb-3 flex size-12 items-center justify-center rounded-full bg-surface-2 text-muted">
        <Icon className="size-6" aria-hidden />
      </div>
      <p className="font-medium text-ink">{title}</p>
      {description ? <p className="mt-1 max-w-sm text-sm text-ink-2">{description}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
