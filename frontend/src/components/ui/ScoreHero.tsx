import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react';
import { cn } from '@/lib/cn';
import type { Grade } from '@/lib/types';
import { GRADE_STYLE } from './styles';

/**
 * Número héroe del dashboard: un único score grande con su calificación.
 * El anillo es un medidor de la misma rampa: relleno = score, pista = paso claro.
 */
export function ScoreHero({
  score,
  grade,
  label,
  description,
  delta,
  deltaLabel,
  size = 'lg',
}: {
  score: number | null;
  grade: Grade | null;
  label: string;
  description?: string;
  delta?: number | null;
  deltaLabel?: string;
  size?: 'lg' | 'md';
}) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const pct = score === null ? 0 : score / 100;
  const ring = grade ? GRADE_STYLE[grade] : null;
  const dim = size === 'lg' ? 'size-36' : 'size-28';

  return (
    <div className="flex flex-col items-center gap-5 sm:flex-row sm:items-center">
      <div className={cn('relative shrink-0', dim)}>
        <svg viewBox="0 0 120 120" className="size-full -rotate-90">
          <circle cx="60" cy="60" r={r} fill="none" strokeWidth="9" className="stroke-line" />
          <circle
            cx="60"
            cy="60"
            r={r}
            fill="none"
            strokeWidth="9"
            strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={c * (1 - pct)}
            className={cn('transition-[stroke-dashoffset] duration-700', ring?.ring ?? 'stroke-muted')}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn('font-semibold leading-none text-ink', size === 'lg' ? 'text-5xl' : 'text-4xl')}>{score ?? '—'}</span>
          <span className="mt-1 text-xs text-muted">de 100</span>
        </div>
      </div>
      <div className="min-w-0 text-center sm:text-left">
        <div className="flex items-center justify-center gap-2 sm:justify-start">
          {grade ? <span className={cn('inline-flex size-8 items-center justify-center rounded-md text-base font-bold text-white', ring?.bg)}>{grade}</span> : null}
          <p className="text-lg font-semibold text-ink">{label}</p>
        </div>
        {description ? <p className="mt-1 max-w-md text-sm text-ink-2">{description}</p> : null}
        {delta !== undefined ? <Delta value={delta} label={deltaLabel} /> : null}
      </div>
    </div>
  );
}

export function Delta({ value, label }: { value: number | null; label?: string }) {
  if (value === null || value === undefined) {
    return <p className="mt-2 text-xs text-muted">{label ? `Sin datos ${label}` : 'Sin datos anteriores'}</p>;
  }
  const Icon = value > 0 ? ArrowUpRight : value < 0 ? ArrowDownRight : Minus;
  const tone = value > 0 ? 'text-good-text' : value < 0 ? 'text-critical' : 'text-muted';
  return (
    <p className={cn('mt-2 inline-flex items-center gap-1 text-sm font-medium', tone)}>
      <Icon className="size-4" aria-hidden />
      {value > 0 ? `+${value}` : value} puntos{label ? ` ${label}` : ''}
    </p>
  );
}
