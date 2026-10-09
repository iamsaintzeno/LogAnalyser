import { useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipContentProps,
  type TooltipValueType,
} from 'recharts';
import type { ThreatType, TimelineBucket } from '../../contracts';
import { fillGaps } from '../../lib/timeline';

const FIVE_MINUTES = 5 * 60_000;
const DAY = 24 * 60 * 60_000;

const THREAT_SERIES: Array<{ type: ThreatType; label: string; color: string; outline: string }> = [
  { type: 'BRUTE_FORCE', label: 'Brute force', color: '#3b82f6', outline: '#1e3a8a' },
  { type: 'SQLI', label: 'SQL injection', color: '#f97316', outline: '#9a3412' },
  { type: 'TRAVERSAL', label: 'Path traversal', color: '#8b5cf6', outline: '#5b21b6' },
  { type: 'SCANNER_UA', label: 'Scanner user agent', color: '#14b8a6', outline: '#115e59' },
  { type: 'SENSITIVE_PROBE', label: 'Sensitive file probe', color: '#eab308', outline: '#854d0e' },
];

interface ChartBucket extends TimelineBucket, Record<ThreatType, number> {
  eventTotal: number;
  isSpike: boolean;
}

function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
}

function formatAxisTime(timestamp: number, includeDate: boolean): string {
  const time = formatTime(timestamp);
  if (!includeDate) return time;

  const date = new Date(timestamp);
  const month = date.toLocaleString(undefined, { month: 'short' });
  return `${String(date.getDate()).padStart(2, '0')} ${month} ${time}`;
}

function eventTotal(bucket: TimelineBucket): number {
  return Object.values(bucket.byType).reduce((sum, count) => sum + count, 0);
}

function EmptyState() {
  return <p className="rounded-lg border border-slate-200 p-6 text-slate-600">No attack activity in this log</p>;
}

function TimelineTooltip({
  active,
  payload,
}: TooltipContentProps<TooltipValueType, string | number>) {
  if (!active || !payload?.length) return null;

  const bucket = payload[0].payload as ChartBucket | undefined;
  if (!bucket) return null;

  const counts = THREAT_SERIES.filter(({ type }) => bucket.byType[type] > 0);

  return (
    <div className="rounded-md border border-slate-200 bg-white p-3 text-sm shadow-md">
      <p className="font-semibold">
        {formatTime(bucket.t)}-{formatTime(bucket.t + FIVE_MINUTES)}
      </p>
      <p className="mt-1">{eventTotal(bucket)} total events</p>
      <ul className="mt-2 space-y-1">
        {counts.map(({ type, label, color }) => (
          <li className="flex items-center gap-2" key={type}>
            <span aria-hidden="true" className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: color }} />
            <span>{label}: {bucket.byType[type]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface AttackTimelineProps {
  buckets: TimelineBucket[];
  onBucketClick?: (t: number) => void;
}

export function AttackTimeline({ buckets, onBucketClick }: AttackTimelineProps) {
  const [visibleTypes, setVisibleTypes] = useState<Set<ThreatType>>(() => new Set(THREAT_SERIES.map(({ type }) => type)));

  if (buckets.length === 0) return <EmptyState />;

  const filledBuckets = fillGaps(buckets);
  const totals = filledBuckets.map(eventTotal);
  const mean = totals.reduce((sum, value) => sum + value, 0) / totals.length;
  const variance = totals.reduce((sum, value) => sum + (value - mean) ** 2, 0) / totals.length;
  const spikeThreshold = mean + 2 * Math.sqrt(variance);
  const chartData: ChartBucket[] = filledBuckets.map((bucket, index) => ({
    ...bucket,
    ...bucket.byType,
    eventTotal: totals[index],
    isSpike: totals[index] > spikeThreshold,
  }));
  const span = chartData[chartData.length - 1].t - chartData[0].t + FIVE_MINUTES;
  const includeDate = span > DAY;
  const scroll = chartData.length > 200;

  function toggleSeries(type: ThreatType) {
    setVisibleTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }

  return (
    <section aria-label="Attack timeline" className="space-y-3">
      <div aria-label="Toggle threat types" className="flex flex-wrap gap-x-4 gap-y-2" role="group">
        {THREAT_SERIES.map(({ type, label, color }) => (
          <button
            aria-pressed={visibleTypes.has(type)}
            className="inline-flex items-center gap-2 text-sm"
            key={type}
            onClick={() => toggleSeries(type)}
            type="button"
          >
            <span aria-hidden="true" className="inline-block h-3 w-3 rounded-sm" style={{ backgroundColor: color }} />
            {label}
          </button>
        ))}
      </div>

      <div className={scroll ? 'overflow-x-auto' : ''}>
        <div
          className="h-[220px] md:h-[280px]"
          style={scroll ? { minWidth: `${Math.max(1000, chartData.length * 8)}px` } : undefined}
        >
          <ResponsiveContainer height="100%" width="100%">
            <BarChart data={chartData} margin={{ top: 12, right: 12, bottom: 4, left: 0 }}>
              <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="t"
                domain={['dataMin', 'dataMax']}
                minTickGap={24}
                scale="time"
                tickFormatter={(value: number) => formatAxisTime(value, includeDate)}
                type="number"
              />
              <YAxis allowDecimals={false} label={{ value: 'Events', angle: -90, position: 'insideLeft' }} />
              <Tooltip content={TimelineTooltip} />
              <ReferenceLine
                label={{ value: 'Spike threshold', position: 'insideTopRight', fill: '#475569', fontSize: 12 }}
                stroke="#475569"
                strokeDasharray="6 4"
                y={spikeThreshold}
                zIndex={400}
              />
              {THREAT_SERIES.filter(({ type }) => visibleTypes.has(type)).map(({ type, color, outline }) => (
                <Bar
                  dataKey={type}
                  fill={color}
                  key={type}
                  name={type}
                  onClick={(bar) => {
                    const t = bar.payload?.t;
                    if (typeof t === 'number') onBucketClick?.(t);
                  }}
                  stackId="threats"
                >
                  {chartData.map((bucket) => (
                    <Cell
                      key={`${type}-${bucket.t}`}
                      stroke={bucket.isSpike ? outline : 'none'}
                      strokeWidth={bucket.isSpike ? 2 : 0}
                    />
                  ))}
                </Bar>
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </section>
  );
}
