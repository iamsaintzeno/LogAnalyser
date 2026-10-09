import type { RiskRating } from '../../contracts';

const RATING_STYLES: Record<RiskRating, { label: string; icon: string; className: string }> = {
  CRITICAL: { label: 'Critical', icon: '▲', className: 'bg-red-100 text-red-800' },
  HIGH: { label: 'High', icon: '●', className: 'bg-orange-100 text-orange-800' },
  MEDIUM: { label: 'Medium', icon: '◆', className: 'bg-yellow-100 text-yellow-900' },
  LOW: { label: 'Low', icon: '✓', className: 'bg-green-100 text-green-800' },
};

export function RiskBadge({ rating }: { rating: RiskRating }) {
  const style = RATING_STYLES[rating];

  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-semibold ${style.className}`}>
      <span aria-hidden="true">{style.icon}</span>
      {style.label}
    </span>
  );
}
