import { TrendingDown, TrendingUp } from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { formatDateTime, formatShortDate } from '@/lib/format';
import type { HistoryPoint } from '@/lib/types';
import { EmptyState } from '../ui/EmptyState';

interface DotProps {
  cx?: number;
  cy?: number;
  payload?: { anomaly?: HistoryPoint['anomaly'] };
}

const renderAnomalyDot = (props: DotProps) => {
  const { cx, cy, payload } = props;
  if (!cx || !cy || !payload?.anomaly) return null;
  const isCritical = payload.anomaly.severity === 'CRITICAL';
  return (
    <g key={`anomaly-dot-${cx}-${cy}`}>
      <circle
        cx={cx}
        cy={cy}
        r={7}
        fill={isCritical ? 'rgba(239, 68, 68, 0.25)' : 'rgba(245, 158, 11, 0.25)'}
        className="animate-pulse"
      />
      <circle
        cx={cx}
        cy={cy}
        r={4}
        fill={isCritical ? 'var(--critical)' : 'var(--warning)'}
        stroke="var(--surface)"
        strokeWidth={1.5}
      />
    </g>
  );
};

/**
 * Serie única: área en el color de acento, línea de 2 px, rejilla hairline,
 * un solo eje y tooltip con crosshair. Destaca automáticamente cualquier
 * anomalía estadística detectada en el histórico del activo u organización.
 */
export function ScoreHistoryChart({ points, height = 220 }: { points: HistoryPoint[]; height?: number }) {
  const data = points
    .filter((p) => p.score !== null)
    .map((p) => ({
      t: new Date(p.computedAt).getTime(),
      score: p.score as number,
      grade: p.grade,
      iso: p.computedAt,
      anomaly: p.anomaly ?? null,
    }));

  if (data.length === 0) {
    return <EmptyState icon={TrendingUp} title="Todavía no hay histórico" description="Aparecerá cuando se complete el primer escaneo." />;
  }
  if (data.length === 1) {
    data.unshift({ ...data[0], t: data[0].t - 1 });
  }

  const hasAnomalies = data.some((d) => Boolean(d.anomaly));

  return (
    <div style={{ height }} className="flex w-full flex-col">
      {hasAnomalies ? (
        <div className="mb-1 flex shrink-0 items-center justify-end">
          <span className="inline-flex items-center gap-1 rounded-md bg-critical/10 px-2 py-0.5 text-[11px] font-medium text-critical">
            <TrendingDown className="size-3" />
            Caída anómala detectada
          </span>
        </div>
      ) : null}
      <div className="min-h-0 flex-1 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <defs>
            <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.28} />
              <stop offset="100%" stopColor="var(--accent)" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid vertical={false} stroke="var(--line)" strokeWidth={1} />
          <XAxis
            dataKey="t"
            type="number"
            domain={['dataMin', 'dataMax']}
            scale="time"
            tickFormatter={(v: number) => formatShortDate(new Date(v).toISOString())}
            tick={{ fill: 'var(--muted)', fontSize: 12 }}
            axisLine={{ stroke: 'var(--line)' }}
            tickLine={false}
            minTickGap={40}
          />
          <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tick={{ fill: 'var(--muted)', fontSize: 12 }} axisLine={false} tickLine={false} />
          <Tooltip
            cursor={{ stroke: 'var(--muted)', strokeDasharray: '3 3' }}
            content={({ active, payload }) => {
              if (!active || !payload?.length) return null;
              const p = payload[0].payload as (typeof data)[number];
              return (
                <div className="rounded-lg border border-border bg-surface px-3 py-2 text-sm shadow-lg">
                  <p className="text-xs text-muted">{formatDateTime(p.iso)}</p>
                  <p className="font-semibold text-ink">
                    Score {p.score}
                    {p.grade ? <span className="ml-1 text-ink-2">· {p.grade}</span> : null}
                  </p>
                  {p.anomaly ? (
                    <div className="mt-1.5 flex items-center gap-1 rounded bg-critical/10 px-1.5 py-0.5 text-xs font-semibold text-critical">
                      <TrendingDown className="size-3.5" />
                      <span>
                        Anomalía: -{p.anomaly.drop} pts
                        {p.anomaly.zScore ? ` (${p.anomaly.zScore}σ)` : ''}
                      </span>
                    </div>
                  ) : null}
                </div>
              );
            }}
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke="var(--accent)"
            strokeWidth={2}
            fill="url(#scoreFill)"
            dot={renderAnomalyDot}
            activeDot={{ r: 5, stroke: 'var(--surface)', strokeWidth: 2, fill: 'var(--accent)' }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  </div>
);
}
