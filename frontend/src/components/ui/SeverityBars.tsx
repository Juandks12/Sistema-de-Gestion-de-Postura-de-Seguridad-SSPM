import { SEVERITY_LABEL, SEVERITY_ORDER } from '@/lib/format';
import type { SeverityCounts } from '@/lib/types';
import { SEVERITY_STYLE } from './styles';
import { cn } from '@/lib/cn';

/** Distribución de hallazgos abiertos por severidad: barra + icono + etiqueta + valor. */
export function SeverityBars({ counts, onSelect }: { counts: SeverityCounts; onSelect?: (s: keyof SeverityCounts) => void }) {
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s] ?? 0));
  return (
    <ul className="space-y-2.5">
      {SEVERITY_ORDER.map((s) => {
        const style = SEVERITY_STYLE[s];
        const Icon = style.icon;
        const n = counts[s] ?? 0;
        const row = (
          <>
            <span className={cn('flex w-28 shrink-0 items-center gap-1.5 text-sm', style.text)}>
              <Icon className="size-4" aria-hidden />
              {SEVERITY_LABEL[s]}
            </span>
            <span className="relative h-2 flex-1 overflow-hidden rounded-full bg-surface-2">
              <span className={cn('absolute inset-y-0 left-0 rounded-full transition-[width] duration-500', style.dot)} style={{ width: `${(n / max) * 100}%` }} />
            </span>
            <span className="tabular w-8 text-right text-sm font-semibold text-ink">{n}</span>
          </>
        );
        return (
          <li key={s}>
            {onSelect ? (
              <button type="button" onClick={() => onSelect(s)} className="flex w-full items-center gap-3 rounded-md px-1 py-0.5 text-left hover:bg-surface-2">
                {row}
              </button>
            ) : (
              <div className="flex items-center gap-3 px-1 py-0.5">{row}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
