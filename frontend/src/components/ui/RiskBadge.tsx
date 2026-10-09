import type { RiskRating } from '../../contracts';

const RATING_STYLES: Record<RiskRating, { label: string; icon: string; className: string }> = {
  CRITICAL: { label: 'Critical', icon: '▲', className: 'text-risk-critical' },
  HIGH: { label: 'High', icon: '●', className: 'text-risk-high' },
  MEDIUM: { label: 'Medium', icon: '◆', className: 'text-risk-medium' },
  LOW: { label: 'Low', icon: '✓', className: 'text-risk-low' },
};

export function RiskBadge({ rating }: { rating: RiskRating }) {
  const style = RATING_STYLES[rating];

  return (
    <span className={`inline-flex items-center gap-1 rounded-full bg-slate-950 px-2 py-1 text-xs font-semibold ${style.className}`}>
      <span aria-hidden="true">{style.icon}</span>
      {style.label}
    </span>
  );
}
