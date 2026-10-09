import { useEffect, useMemo, useRef, useState, type MouseEvent } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { LogEntry, ThreatEvent, ThreatType, TimelineBucket } from '../../contracts';
import { WEIGHTS } from '../../contracts';
import { copyText } from '../../lib/clipboard';
import { RiskBadge } from '../ui/RiskBadge';
import { useAnalyzerStore } from '../../store/useAnalyzerStore';

const PAGE_SIZE = 50;
const BUCKET_MS = 5 * 60_000;

const THREAT_TYPES: ThreatType[] = [
  'BRUTE_FORCE',
  'SQLI',
  'TRAVERSAL',
  'SCANNER_UA',
  'SENSITIVE_PROBE',
];

const THREAT_LABELS: Record<ThreatType, string> = {
  BRUTE_FORCE: 'Brute force',
  SQLI: 'SQL injection',
  TRAVERSAL: 'Path traversal',
  SCANNER_UA: 'Hacking tool',
  SENSITIVE_PROBE: 'Sensitive file probe',
};

const THREAT_COLORS: Record<ThreatType, string> = {
  BRUTE_FORCE: 'bg-blue-100 text-blue-800',
  SQLI: 'bg-orange-100 text-orange-800',
  TRAVERSAL: 'bg-violet-100 text-violet-800',
  SCANNER_UA: 'bg-teal-100 text-teal-800',
  SENSITIVE_PROBE: 'bg-yellow-100 text-yellow-900',
};

const RISK_STROKES = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#facc15',
  LOW: '#22c55e',
} as const;

function formatLocalDateTime(timestamp: number): string {
  const date = new Date(timestamp);
  const day = String(date.getDate()).padStart(2, '0');
  const month = date.toLocaleString(undefined, { month: 'short' });
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${day} ${month} ${hours}:${minutes}:${seconds}`;
}

function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

function truncate(value: string, length = 80): string {
  if (value.length <= length) return value;
  return `${value.slice(0, length - 3)}...`;
}

function isPrivateOrLoopback(ip: string): boolean {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  const octets = ip.split('.').map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) return false;
  const [first, second] = octets;
  return first === 10 || first === 127 ||
    (first === 192 && second === 168) ||
    (first === 172 && second >= 16 && second <= 31);
}

function makeIpTimeline(events: ThreatEvent[]): TimelineBucket[] {
  const buckets = new Map<number, TimelineBucket>();

  for (const event of events) {
    const t = Math.floor(event.ts / BUCKET_MS) * BUCKET_MS;
    const bucket = buckets.get(t) ?? {
      t,
      total: 0,
      byType: {
        BRUTE_FORCE: 0,
        SQLI: 0,
        TRAVERSAL: 0,
        SCANNER_UA: 0,
        SENSITIVE_PROBE: 0,
      },
    };
    bucket.byType[event.type] += 1;
    bucket.total += 1;
    buckets.set(t, bucket);
  }

  const sorted = [...buckets.values()].sort((left, right) => left.t - right.t);
  if (sorted.length < 2) return sorted;

  const byTime = new Map(sorted.map((bucket) => [bucket.t, bucket]));
  const filled: TimelineBucket[] = [];
  for (let t = sorted[0].t; t <= sorted[sorted.length - 1].t; t += BUCKET_MS) {
    filled.push(byTime.get(t) ?? {
      t,
      total: 0,
      byType: {
        BRUTE_FORCE: 0,
        SQLI: 0,
        TRAVERSAL: 0,
        SCANNER_UA: 0,
        SENSITIVE_PROBE: 0,
      },
    });
  }
  return filled;
}

function ScoreRing({ score, rating }: { score: number; rating: keyof typeof RISK_STROKES }) {
  const boundedScore = Math.min(100, Math.max(0, score));
  const circumference = 2 * Math.PI * 44;
  const dashOffset = circumference * (1 - boundedScore / 100);

  return (
    <svg aria-label={`Risk score ${boundedScore} out of 100`} className="h-28 w-28" role="img" viewBox="0 0 100 100">
      <circle cx="50" cy="50" fill="none" r="44" stroke="#e2e8f0" strokeWidth="8" />
      <circle
        cx="50"
        cy="50"
        fill="none"
        r="44"
        stroke={RISK_STROKES[rating]}
        strokeDasharray={circumference}
        strokeDashoffset={dashOffset}
        strokeLinecap="round"
        strokeWidth="8"
        transform="rotate(-90 50 50)"
      />
      <text dominantBaseline="middle" textAnchor="middle" x="50" y="50" className="fill-slate-900 text-xl font-semibold">
        {boundedScore}
      </text>
      <text dominantBaseline="middle" textAnchor="middle" x="50" y="68" className="fill-slate-500 text-[8px]">
        RISK SCORE
      </text>
    </svg>
  );
}

interface EvidenceRow {
  event: ThreatEvent;
  entry: LogEntry | undefined;
}

export interface IpDetailModalProps {
  ip: string;
  onClose: () => void;
}

export function IpDetailModal({ ip, onClose }: IpDetailModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  const result = useAnalyzerStore((state) => state.result);
  const addToBlocklist = useAnalyzerStore((state) => state.addToBlocklist);
  const isBlocked = useAnalyzerStore((state) => state.blocklist.some((rule) => rule.ip === ip && rule.enabled));
  const [selectedType, setSelectedType] = useState<ThreatType | 'ALL'>('ALL');
  const [page, setPage] = useState(0);
  const [copiedAction, setCopiedAction] = useState<string | null>(null);
  const [copiedEventId, setCopiedEventId] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const copyTimer = useRef<number | null>(null);
  const rawCopyTimer = useRef<number | null>(null);

  onCloseRef.current = onClose;

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    const previousFocus = document.activeElement;
    dialog.showModal();
    closeButtonRef.current?.focus();

    return () => {
      if (dialog.open) dialog.close();
      if (previousFocus instanceof HTMLElement) previousFocus.focus();
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
      if (rawCopyTimer.current !== null) window.clearTimeout(rawCopyTimer.current);
    };
  }, []);

  const attacker = result?.session.summaries.find((summary) => summary.ip === ip);
  const events = useMemo(
    () => (result?.events ?? []).filter((event) => event.ip === ip).sort((left, right) => left.ts - right.ts),
    [ip, result],
  );
  const timeline = useMemo(() => makeIpTimeline(events), [events]);
  const entriesById = useMemo(() => new Map((result?.entries ?? []).map((entry) => [entry.id, entry])), [result]);
  const filteredEvents = useMemo(
    () => events.filter((event) => selectedType === 'ALL' || event.type === selectedType),
    [events, selectedType],
  );
  const evidenceRows: EvidenceRow[] = filteredEvents.map((event) => ({ event, entry: entriesById.get(event.entryId) }));
  const pageCount = Math.max(1, Math.ceil(evidenceRows.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const pageRows = evidenceRows.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);

  function copyWithFeedback(key: string, text: string, label: string) {
    void copyText(text).then((copied) => {
      if (!copied) {
        setAnnouncement(`Could not copy ${label}.`);
        return;
      }
      setCopiedAction(key);
      setAnnouncement(`${label} copied to clipboard.`);
      if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopiedAction(null), 1500);
    });
  }

  function copyRawLine(eventId: string, raw: string | undefined) {
    if (raw === undefined) return;
    void copyText(raw).then((copied) => {
      if (!copied) {
        setAnnouncement('Could not copy raw line.');
        return;
      }
      setCopiedEventId(eventId);
      setAnnouncement('Raw log line copied to clipboard.');
      if (rawCopyTimer.current !== null) window.clearTimeout(rawCopyTimer.current);
      rawCopyTimer.current = window.setTimeout(() => setCopiedEventId(null), 1500);
    });
  }

  function handleDialogClick(event: MouseEvent<HTMLDialogElement>) {
    if (event.target === event.currentTarget) onCloseRef.current();
  }

  if (!result || !attacker) return null;

  const privateIP = isPrivateOrLoopback(ip);
  const visibleStart = evidenceRows.length === 0 ? 0 : currentPage * PAGE_SIZE + 1;
  const visibleEnd = Math.min((currentPage + 1) * PAGE_SIZE, evidenceRows.length);

  return (
    <dialog
      aria-labelledby="ip-detail-title"
      aria-modal="true"
      className="m-auto max-h-[90vh] w-[min(1100px,95vw)] overflow-y-auto rounded-xl p-0 backdrop:bg-black/50"
      onCancel={(event) => {
        event.preventDefault();
        onCloseRef.current();
      }}
      onClick={handleDialogClick}
      ref={dialogRef}
    >
      <div className="space-y-6 p-5 sm:p-6">
        <header className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h2 className="break-all text-2xl font-semibold" id="ip-detail-title">{attacker.ip}</h2>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <RiskBadge rating={attacker.rating} />
              <span>{formatNumber(attacker.totalHits)} total hits</span>
            </div>
            <p className="mt-3 break-all text-sm text-slate-600">
              First seen {formatLocalDateTime(attacker.firstSeen)} · Last seen {formatLocalDateTime(attacker.lastSeen)}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              Times shown in {Intl.DateTimeFormat().resolvedOptions().timeZone || 'your local timezone'}.
            </p>
          </div>
          <ScoreRing rating={attacker.rating} score={attacker.score} />
          <button
            aria-label="Close IP details"
            className="rounded border border-slate-300 px-3 py-2"
            onClick={onClose}
            ref={closeButtonRef}
            type="button"
          >
            Close
          </button>
        </header>

        {privateIP && (
          <p className="rounded-md border border-amber-300 bg-amber-50 p-3 text-amber-900" role="alert">
            Internal IP - blocking it may lock you out
          </p>
        )}

        <section className="space-y-3">
          <h3 className="text-lg font-semibold">Why this score</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-slate-200 text-left">
                <th className="py-2 pr-4">Threat type</th>
                <th className="py-2 pr-4">Count</th>
                <th className="py-2">Points contributed</th>
              </tr></thead>
              <tbody>
                {THREAT_TYPES.map((type) => (
                  <tr className="border-b border-slate-100" key={type}>
                    <td className="break-all py-2 pr-4">{THREAT_LABELS[type]}</td>
                    <td className="py-2 pr-4">{formatNumber(attacker.byType[type])}</td>
                    <td className="py-2">{formatNumber(attacker.byType[type] * WEIGHTS[type])}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="space-y-3">
          <h3 className="text-lg font-semibold">Activity over time</h3>
          {timeline.length === 0 ? (
            <p className="text-sm text-slate-600">No timeline activity for this IP.</p>
          ) : (
            <div aria-label="Five-minute threat event timeline for this IP" className="h-40 w-full">
              <ResponsiveContainer height="100%" width="100%">
                <AreaChart data={timeline} margin={{ top: 8, right: 12, bottom: 0, left: -20 }}>
                  <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="t" tickFormatter={formatTime} />
                  <YAxis allowDecimals={false} />
                  <Tooltip labelFormatter={(value) => formatTime(Number(value))} />
                  <Area dataKey="total" fill="#bfdbfe" fillOpacity={0.7} name="Threat events" stroke="#2563eb" type="monotone" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h3 className="text-lg font-semibold">Evidence</h3>
            <label className="flex items-center gap-2 text-sm">
              <span>Threat type</span>
              <select
                className="rounded border border-slate-300 px-2 py-1"
                onChange={(event) => {
                  setSelectedType(event.currentTarget.value as ThreatType | 'ALL');
                  setPage(0);
                }}
                value={selectedType}
              >
                <option value="ALL">All types</option>
                {THREAT_TYPES.map((type) => <option key={type} value={type}>{THREAT_LABELS[type]}</option>)}
              </select>
            </label>
          </div>

          {evidenceRows.length === 0 ? (
            <p className="text-sm text-slate-600">No threat events for this IP.</p>
          ) : (
            <>
              <div className="overflow-x-auto rounded-lg border border-slate-200">
                <table className="w-full min-w-[900px] text-sm">
                  <thead className="bg-slate-50 text-left">
                    <tr>
                      <th className="p-2">Time</th><th className="p-2">Type</th><th className="p-2">Method</th>
                      <th className="p-2">Path + query</th><th className="p-2">Status</th><th className="p-2">User agent</th>
                      <th className="p-2">Referer</th>
                      <th className="p-2">Evidence</th><th className="p-2">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageRows.map(({ event, entry }) => {
                      const pathQuery = entry ? `${entry.path}${entry.query ? `?${entry.query}` : ''}` : '';
                      return (
                        <tr className="border-t border-slate-200 align-top" key={event.id}>
                          <td className="whitespace-nowrap p-2">{formatLocalDateTime(event.ts)}</td>
                          <td className="p-2">
                            <span className={`break-all rounded-full px-2 py-1 text-xs ${THREAT_COLORS[event.type]}`}>
                              {THREAT_LABELS[event.type]}
                            </span>
                          </td>
                          <td className="break-all p-2">{entry?.method ?? ''}</td>
                          <td className="max-w-52 break-all p-2" title={pathQuery}>{truncate(pathQuery)}</td>
                          <td className="p-2">{entry?.status ?? ''}</td>
                          <td className="max-w-40 break-all p-2" title={entry?.ua ?? ''}>{truncate(entry?.ua ?? '')}</td>
                          <td className="max-w-40 break-all p-2" title={entry?.referer ?? ''}>{truncate(entry?.referer ?? '')}</td>
                          <td className="max-w-56 break-all p-2">{event.evidence}</td>
                          <td className="p-2">
                            <button
                              className="whitespace-nowrap rounded border border-slate-300 px-2 py-1 text-xs disabled:opacity-50"
                              disabled={entry === undefined}
                              onClick={() => copyRawLine(event.id, entry?.raw)}
                              type="button"
                            >
                              {copiedEventId === event.id ? 'Copied!' : 'Copy raw line'}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <div className="flex items-center justify-between gap-3 text-sm">
                <p>Showing {visibleStart}-{visibleEnd} of {evidenceRows.length} events</p>
                <div className="flex gap-2">
                  <button
                    className="rounded border border-slate-300 px-3 py-1 disabled:opacity-50"
                    disabled={currentPage === 0}
                    onClick={() => setPage(currentPage - 1)}
                    type="button"
                  >Previous</button>
                  <button
                    className="rounded border border-slate-300 px-3 py-1 disabled:opacity-50"
                    disabled={currentPage >= pageCount - 1}
                    onClick={() => setPage(currentPage + 1)}
                    type="button"
                  >Next</button>
                </div>
              </div>
            </>
          )}
        </section>

        <footer className="flex flex-wrap gap-2 border-t border-slate-200 pt-4">
          <button className="rounded border border-slate-300 px-3 py-2 text-sm" onClick={() => copyWithFeedback('ip', ip, 'IP address')} type="button">
            {copiedAction === 'ip' ? 'Copied!' : 'Copy IP'}
          </button>
          <button
            className="rounded border border-slate-300 px-3 py-2 text-sm"
            onClick={() => copyWithFeedback('iptables', `iptables -A INPUT -s ${ip} -j DROP`, 'iptables rule')}
            type="button"
          >
            {copiedAction === 'iptables' ? 'Copied!' : 'Copy iptables rule'}
          </button>
          <button
            className="rounded border border-slate-300 px-3 py-2 text-sm"
            onClick={() => copyWithFeedback('htaccess', `Deny from ${ip}`, '.htaccess rule')}
            type="button"
          >
            {copiedAction === 'htaccess' ? 'Copied!' : 'Copy .htaccess rule'}
          </button>
          <button
            className="rounded border border-slate-300 bg-slate-900 px-3 py-2 text-sm text-white disabled:opacity-60"
            disabled={isBlocked}
            onClick={() => addToBlocklist(ip)}
            type="button"
          >
            {isBlocked ? 'In blocklist' : 'Add to blocklist'}
          </button>
          <button className="ml-auto rounded border border-slate-300 px-3 py-2 text-sm" onClick={onClose} type="button">
            Close
          </button>
        </footer>
        <p aria-live="polite" className="sr-only" role="status">{announcement}</p>
      </div>
    </dialog>
  );
}
