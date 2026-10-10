import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import type { AttackerIPSummary, RiskRating, ThreatType } from '../../contracts';
import { copyText } from '../../lib/clipboard';
import { RiskBadge } from '../ui/RiskBadge';

const PAGE_SIZE = 25;

const THREAT_LABELS: Record<ThreatType, string> = {
  BRUTE_FORCE: 'Brute force',
  SQLI: 'SQL injection',
  TRAVERSAL: 'Path traversal',
  SCANNER_UA: 'Hacking tool',
  SENSITIVE_PROBE: 'Sensitive file probe',
};

const THREAT_CHIP_COLORS: Record<ThreatType, string> = {
  BRUTE_FORCE: 'bg-blue-100 text-blue-800',
  SQLI: 'bg-orange-100 text-orange-800',
  TRAVERSAL: 'bg-violet-100 text-violet-800',
  SCANNER_UA: 'bg-teal-100 text-teal-800',
  SENSITIVE_PROBE: 'bg-yellow-100 text-yellow-900',
};

const RISK_BAR_COLORS: Record<RiskRating, string> = {
  CRITICAL: 'bg-risk-critical',
  HIGH: 'bg-risk-high',
  MEDIUM: 'bg-risk-medium',
  LOW: 'bg-risk-low',
};

type SortKey = 'rank' | 'ip' | 'totalHits' | 'mainThreat' | 'risk' | 'seen' | 'actions';
type SortDirection = 'asc' | 'desc';

interface SortState {
  key: SortKey;
  direction: SortDirection;
}

interface IndexedRow {
  row: AttackerIPSummary;
  index: number;
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

function formatLocalDateTime(timestamp: number): string {
  const date = new Date(timestamp);
  const day = String(date.getDate()).padStart(2, '0');
  const month = date.toLocaleString(undefined, { month: 'short' });
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${day} ${month} ${hours}:${minutes}:${seconds}`;
}

function EmptyState() {
  return <p className="rounded-lg border border-slate-200 p-6 text-slate-600">No attackers match these filters</p>;
}

function AttackerTableSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading attackers" className="space-y-3" role="status">
      <div aria-hidden="true" className="overflow-x-auto rounded-lg border border-slate-200">
        <table className="w-full min-w-[760px] border-collapse text-sm">
          <thead className="bg-slate-50">
            <tr>
              {[12, 24, 20, 28, 20, 36, 24].map((width, index) => (
                <th className={`px-3 py-3 ${index === 2 || index === 5 ? 'hidden sm:table-cell' : ''}`} key={index}>
                  <span className="block h-4 animate-pulse rounded bg-slate-300" style={{ width: `${width * 2}px` }} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: 5 }, (_, row) => (
              <tr className="border-t border-slate-200" key={row}>
                {[12, 24, 20, 28, 20, 36, 24].map((width, column) => (
                  <td className={`px-3 py-3 ${column === 2 || column === 5 ? 'hidden sm:table-cell' : ''}`} key={column}>
                    <span className="block h-4 animate-pulse rounded bg-slate-200" style={{ width: `${width * 2}px` }} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex justify-between" aria-hidden="true">
        <span className="h-8 w-28 animate-pulse rounded bg-slate-200" />
        <span className="h-8 w-24 animate-pulse rounded bg-slate-200" />
      </div>
    </div>
  );
}

function SortHeader({
  label,
  sortKey,
  sort,
  onSort,
  className = '',
}: {
  label: string;
  sortKey: SortKey;
  sort: SortState;
  onSort: (key: SortKey) => void;
  className?: string;
}) {
  const active = sort.key === sortKey;
  return (
    <th aria-sort={active ? (sort.direction === 'asc' ? 'ascending' : 'descending') : 'none'} className={`px-3 py-2 text-left ${className}`}>
      <button className="inline-flex items-center gap-1 font-semibold" onClick={() => onSort(sortKey)} type="button">
        {label}
        <span aria-hidden="true">{active ? (sort.direction === 'asc' ? '↑' : '↓') : '↕'}</span>
      </button>
    </th>
  );
}

function RiskScore({ score, rating }: { score: number; rating: RiskRating }) {
  const boundedScore = Math.min(100, Math.max(0, score));

  return (
    <div className="flex min-w-28 items-center gap-2">
      <span className="w-7 text-right font-mono text-xs">{formatNumber(boundedScore)}</span>
      <span
        aria-label={`Risk score ${boundedScore} out of 100`}
        aria-valuemax={100}
        aria-valuemin={0}
        aria-valuenow={boundedScore}
        className="h-2 w-14 overflow-hidden rounded-full bg-slate-950"
        role="progressbar"
      >
        <span className={`block h-full ${RISK_BAR_COLORS[rating]}`} style={{ width: `${boundedScore}%` }} />
      </span>
      <RiskBadge rating={rating} />
    </div>
  );
}

export interface AttackerTableProps {
  rows: AttackerIPSummary[];
  onRowClick: (ip: string) => void;
  loading?: boolean;
}

export function AttackerTable({ rows, onRowClick, loading = false }: AttackerTableProps) {
  const [sort, setSort] = useState<SortState>({ key: 'risk', direction: 'desc' });
  const [page, setPage] = useState(0);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const copyTimers = useRef(new Map<string, number>());

  useEffect(() => () => {
    for (const timer of copyTimers.current.values()) window.clearTimeout(timer);
  }, []);

  const sortedRows = useMemo(() => {
    const indexedRows: IndexedRow[] = rows.map((row, index) => ({ row, index }));
    const direction = sort.direction === 'asc' ? 1 : -1;

    indexedRows.sort((left, right) => {
      let comparison = 0;
      switch (sort.key) {
        case 'rank':
        case 'actions':
          comparison = left.index - right.index;
          break;
        case 'ip':
          comparison = left.row.ip.localeCompare(right.row.ip);
          break;
        case 'totalHits':
          comparison = left.row.totalHits - right.row.totalHits;
          break;
        case 'mainThreat':
          comparison = THREAT_LABELS[left.row.mainThreat].localeCompare(THREAT_LABELS[right.row.mainThreat]);
          break;
        case 'risk':
          comparison = left.row.score - right.row.score;
          break;
        case 'seen':
          comparison = left.row.firstSeen - right.row.firstSeen;
          break;
      }

      if (comparison !== 0) return comparison * direction;
      if (left.row.totalHits !== right.row.totalHits) return right.row.totalHits - left.row.totalHits;
      return left.index - right.index;
    });

    return indexedRows;
  }, [rows, sort]);

  if (loading) return <AttackerTableSkeleton />;
  if (rows.length === 0) return <EmptyState />;

  const pageCount = Math.ceil(sortedRows.length / PAGE_SIZE);
  const currentPage = Math.min(page, pageCount - 1);
  const firstIndex = currentPage * PAGE_SIZE;
  const pageRows = sortedRows.slice(firstIndex, firstIndex + PAGE_SIZE);
  const firstShown = firstIndex + 1;
  const lastShown = Math.min(firstIndex + PAGE_SIZE, sortedRows.length);

  function handleSort(key: SortKey) {
    setSort((current) => ({
      key,
      direction: current.key === key
        ? (current.direction === 'asc' ? 'desc' : 'asc')
        : 'asc',
    }));
    setPage(0);
  }

  async function handleCopy(key: string, text: string, description: string) {
    const copied = await copyText(text);
    const existingTimer = copyTimers.current.get(key);
    if (existingTimer !== undefined) window.clearTimeout(existingTimer);

    if (!copied) {
      setCopiedKey(null);
      setAnnouncement(`Could not copy ${description}.`);
      return;
    }

    setCopiedKey(key);
    setAnnouncement(`${description} copied to clipboard.`);
    const timer = window.setTimeout(() => {
      setCopiedKey((current) => current === key ? null : current);
      copyTimers.current.delete(key);
    }, 1500);
    copyTimers.current.set(key, timer);
  }

  function handleRowKeyDown(event: KeyboardEvent<HTMLTableRowElement>, ip: string) {
    if (event.key === 'Enter' && event.target === event.currentTarget) {
      event.preventDefault();
      onRowClick(ip);
    }
  }

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-lg border border-slate-200">
        <table className="w-full min-w-[760px] border-collapse text-sm">
          <thead className="bg-slate-50">
            <tr>
              <SortHeader label="Rank" sortKey="rank" sort={sort} onSort={handleSort} />
              <SortHeader label="IP" sortKey="ip" sort={sort} onSort={handleSort} />
              <SortHeader label="Total Hits" sortKey="totalHits" sort={sort} onSort={handleSort} className="hidden sm:table-cell" />
              <SortHeader label="Main Threat" sortKey="mainThreat" sort={sort} onSort={handleSort} />
              <SortHeader label="Risk" sortKey="risk" sort={sort} onSort={handleSort} />
              <SortHeader label="First seen - Last seen" sortKey="seen" sort={sort} onSort={handleSort} className="hidden sm:table-cell" />
              <SortHeader label="Actions" sortKey="actions" sort={sort} onSort={handleSort} />
            </tr>
          </thead>
          <tbody>
            {pageRows.map(({ row }, index) => {
              const rank = firstIndex + index + 1;
              return (
                <tr
                  aria-label={`Open attacker ${row.ip}`}
                  className="border-t border-slate-200 hover:bg-slate-50 focus:bg-slate-50 focus:outline-none"
                  key={`${row.ip}-${rank}`}
                  onClick={() => onRowClick(row.ip)}
                  onKeyDown={(event) => handleRowKeyDown(event, row.ip)}
                  tabIndex={0}
                >
                  <td className="px-3 py-3">{rank}</td>
                  <td className="px-3 py-3 font-mono">{row.ip}</td>
                  <td className="hidden px-3 py-3 sm:table-cell">{formatNumber(row.totalHits)}</td>
                  <td className="px-3 py-3">
                      <span className={`whitespace-nowrap rounded-full px-2 py-1 text-xs ${THREAT_CHIP_COLORS[row.mainThreat]}`}>
                      {THREAT_LABELS[row.mainThreat]}
                    </span>
                  </td>
                  <td className="px-3 py-3"><RiskScore score={row.score} rating={row.rating} /></td>
                  <td className="hidden whitespace-nowrap px-3 py-3 sm:table-cell">
                    {formatLocalDateTime(row.firstSeen)} - {formatLocalDateTime(row.lastSeen)}
                  </td>
                  <td className="px-3 py-3">
                    <div className="flex flex-wrap gap-2">
                      {([
                        { suffix: 'ip', label: 'Copy IP', text: row.ip },
                        { suffix: 'htaccess', label: 'Copy .htaccess', text: `Deny from ${row.ip}` },
                      ] as const).map(({ suffix, label, text }) => {
                        const key = `${row.ip}:${suffix}`;
                        const copied = copiedKey === key;
                        return (
                          <button
                            className="whitespace-nowrap rounded border border-slate-300 px-2 py-1 text-xs hover:bg-white"
                            key={suffix}
                            onClick={(event) => {
                              event.stopPropagation();
                              void handleCopy(key, text, suffix === 'ip' ? 'IP address' : '.htaccess rule');
                            }}
                            type="button"
                          >
                            {copied ? 'Copied!' : label}
                          </button>
                        );
                      })}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p aria-live="polite" className="sr-only" role="status">{announcement}</p>
      <div className="flex items-center justify-between gap-4 text-sm">
        <p>Showing {firstShown}-{lastShown} of {formatNumber(sortedRows.length)}</p>
        <div className="flex gap-2">
          <button
            className="rounded border border-slate-300 px-3 py-1 disabled:opacity-50"
            disabled={currentPage === 0}
            onClick={() => setPage(currentPage - 1)}
            type="button"
          >
            Previous
          </button>
          <button
            className="rounded border border-slate-300 px-3 py-1 disabled:opacity-50"
            disabled={currentPage >= pageCount - 1}
            onClick={() => setPage(currentPage + 1)}
            type="button"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
