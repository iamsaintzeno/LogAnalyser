import { useEffect, useState } from 'react';
import type { ParseResult } from '../../contracts';
import { countByRating, countUniqueThreatIPs, getPeakBucket } from '../../lib/summaryStats';

interface SummaryCardsProps {
  result: ParseResult;
  loading?: boolean;
}

function useCountUp(target: number): number {
  const [value, setValue] = useState(0);

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setValue(target);
      return;
    }

    const startTime = performance.now();
    let frame = 0;
    setValue(0);

    function update(now: number) {
      const progress = Math.min((now - startTime) / 400, 1);
      setValue(Math.round(target * progress));
      if (progress < 1) frame = window.requestAnimationFrame(update);
    }

    frame = window.requestAnimationFrame(update);
    return () => window.cancelAnimationFrame(frame);
  }, [target]);

  return value;
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
}

function SummaryCard({
  title,
  value,
  subtext,
  accent = 'border-slate-200',
  valueClassName = '',
}: {
  title: string;
  value: string;
  subtext: string;
  accent?: string;
  valueClassName?: string;
}) {
  return (
    <article className={`rounded-lg border ${accent} p-4`}>
      <h2 className="text-sm font-medium text-slate-600">{title}</h2>
      <p className={`mt-2 text-2xl font-semibold ${valueClassName}`}>{value}</p>
      <p className="mt-1 text-sm text-slate-600">{subtext}</p>
    </article>
  );
}

function SummaryCardsSkeleton() {
  return (
    <div aria-label="Loading summary" aria-busy="true" className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {Array.from({ length: 4 }, (_, index) => (
        <div className="space-y-3 rounded-lg border border-slate-200 p-4" key={index}>
          <div className="h-4 w-2/3 animate-pulse rounded bg-slate-200" />
          <div className="h-8 w-1/2 animate-pulse rounded bg-slate-200" />
          <div className="h-4 w-5/6 animate-pulse rounded bg-slate-200" />
        </div>
      ))}
    </div>
  );
}

export function SummaryCards({ result, loading = false }: SummaryCardsProps) {
  const { session } = result;
  const ratings = countByRating(session.summaries);
  const totalLines = useCountUp(session.totalLines);
  const threatsFound = useCountUp(session.threatCount);
  const criticalIPs = useCountUp(ratings.CRITICAL);
  const uniqueThreatIPs = countUniqueThreatIPs(session.summaries);
  const peak = getPeakBucket(session.timeline);
  const peakEventCount = useCountUp(peak?.eventCount ?? 0);

  if (loading) return <SummaryCardsSkeleton />;

  const peakTime = peak
    ? `${formatTime(peak.bucket.t)}-${formatTime(peak.bucket.t + 5 * 60_000)}`
    : 'No attack spike';
  const criticalAccent = ratings.CRITICAL === 0
    ? 'border-green-500'
    : 'border-red-500';
  const criticalValue = ratings.CRITICAL === 0
    ? 'No critical IPs'
    : formatNumber(criticalIPs);

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <SummaryCard
        title="Total Log Lines"
        value={formatNumber(totalLines)}
        subtext={`${formatNumber(session.skippedLines)} unparseable lines skipped`}
      />
      <SummaryCard
        title="Threats Found"
        value={formatNumber(threatsFound)}
        subtext={`from ${formatNumber(uniqueThreatIPs)} unique IPs`}
      />
      <SummaryCard
        accent={criticalAccent}
        title="Critical IPs"
        value={criticalValue}
        subtext={`${formatNumber(ratings.HIGH)} more rated HIGH`}
        valueClassName={ratings.CRITICAL === 0 ? 'text-green-700' : 'text-red-700'}
      />
      <SummaryCard
        title="High-Risk Peak Time"
        value={peakTime}
        subtext={peak ? `${formatNumber(peakEventCount)} events` : ''}
      />
    </div>
  );
}
