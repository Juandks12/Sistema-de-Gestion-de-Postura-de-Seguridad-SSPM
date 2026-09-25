import type { ReactNode, TdHTMLAttributes, ThHTMLAttributes } from 'react';
import { cn } from '@/lib/cn';

export function Table({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className="scroll-x">
      <table className={cn('w-full border-collapse text-sm', className)}>{children}</table>
    </div>
  );
}

export function Th({ className, children, ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th scope="col" className={cn('border-b border-line px-3 py-2.5 text-left text-xs font-semibold tracking-wide text-muted uppercase first:pl-5 last:pr-5', className)} {...rest}>
      {children}
    </th>
  );
}

export function Td({ className, children, ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={cn('border-b border-line px-3 py-3 align-middle text-ink first:pl-5 last:pr-5', className)} {...rest}>
      {children}
    </td>
  );
}
