import { useMemo, useRef, useState } from 'react';
import type { BlocklistRule } from '../../contracts';
import { copyText } from '../../lib/clipboard';
import { generateBlocklist, type BlocklistFormat } from '../../lib/blocklist';
import { useAnalyzerStore } from '../../store/useAnalyzerStore';

const FORMATS: Array<{ format: BlocklistFormat; label: string; location: string }> = [
  { format: 'htaccess24', label: '.htaccess (Apache 2.4)', location: 'top of .htaccess' },
  { format: 'htaccess22', label: '.htaccess (Apache 2.2)', location: 'top of .htaccess' },
  { format: 'iptables', label: 'iptables', location: 'root shell/iptables' },
  { format: 'nginx', label: 'nginx', location: 'inside server{} for nginx' },
  { format: 'plain', label: 'Plain IP list', location: 'one IP per line' },
];

interface Candidate {
  ip: string;
  score: number;
  manual: boolean;
}

function EmptyState({ message }: { message: string }) {
  return <p className="rounded border border-slate-200 p-4 text-sm text-slate-600">{message}</p>;
}

function makeRule(candidate: Candidate, format: BlocklistFormat): BlocklistRule {
  return {
    ip: candidate.ip,
    format,
    reason: candidate.manual ? 'Manually added' : 'Risk score threshold',
    score: candidate.score,
    enabled: true,
  };
}

export function BlocklistPanel({ disabled = false }: { disabled?: boolean }) {
  const summaries = useAnalyzerStore((state) => state.result?.session.summaries ?? []);
  const manualRules = useAnalyzerStore((state) => state.blocklist);
  const [minScore, setMinScore] = useState(60);
  const [format, setFormat] = useState<BlocklistFormat>('htaccess24');
  const [excludedIPs, setExcludedIPs] = useState<Set<string>>(() => new Set());
  const [announcement, setAnnouncement] = useState('');
  const outputRef = useRef<HTMLPreElement>(null);

  const candidates = useMemo(() => {
    const byIP = new Map<string, Candidate>();
    for (const summary of summaries) {
      if (summary.score >= minScore) {
        byIP.set(summary.ip, { ip: summary.ip, score: summary.score, manual: false });
      }
    }
    for (const rule of manualRules) {
      byIP.set(rule.ip, {
        ip: rule.ip,
        score: summaries.find((summary) => summary.ip === rule.ip)?.score ?? rule.score,
        manual: true,
      });
    }
    return [...byIP.values()].sort((left, right) => right.score - left.score || left.ip.localeCompare(right.ip));
  }, [manualRules, minScore, summaries]);
  const availableCandidates = disabled ? [] : candidates;

  const selectedCandidates = availableCandidates.filter((candidate) => !excludedIPs.has(candidate.ip));
  const rules = selectedCandidates.map((candidate) => makeRule(candidate, format));
  const output = generateBlocklist(rules, format, minScore);
  const lines = output.split('\n');

  function toggleCandidate(ip: string) {
    setExcludedIPs((current) => {
      const next = new Set(current);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  }

  async function handleCopyAll() {
    const copied = await copyText(output);
    setAnnouncement(copied ? 'Blocklist copied to clipboard.' : 'Could not copy blocklist.');
  }

  function handleDownload() {
    const blob = new Blob([output], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `logguard-blocklist-${format}.txt`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function handleSelectAll() {
    const pre = outputRef.current;
    if (!pre) return;
    const range = document.createRange();
    range.selectNodeContents(pre);
    const selection = window.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
  }

  return (
    <section aria-labelledby="blocklist-heading" className="space-y-4 rounded-lg border border-slate-200 p-4">
      <div className="space-y-1">
        <h2 className="text-xl font-semibold" id="blocklist-heading">Blocklist</h2>
        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950" role="note">
          <p className="font-medium">Review this list. Blocking shared/NAT or internal IPs can block real visitors.</p>
          <ul className="mt-2 list-inside list-disc space-y-1">
            <li>Apache snippets: top of .htaccess</li>
            <li>iptables: root shell/iptables</li>
            <li>nginx: inside server{'{}'}</li>
            <li>Plain list: one IP per line</li>
          </ul>
        </div>
      </div>

      {disabled && <p className="text-sm text-slate-600">Blocklist is disabled because no threats were detected.</p>}

      <div role="tablist" aria-label="Blocklist format" className="flex flex-wrap gap-2">
        {FORMATS.map((item) => (
          <button
            aria-selected={format === item.format}
            className={`rounded border px-3 py-2 text-sm ${format === item.format ? 'border-cyan-600 bg-cyan-50 text-cyan-900' : 'border-slate-300'}`}
            key={item.format}
            onClick={() => setFormat(item.format)}
            disabled={disabled}
            role="tab"
            type="button"
          >
            {item.label}
          </button>
        ))}
      </div>
      <p className="text-sm text-slate-600">Place this snippet at the {FORMATS.find((item) => item.format === format)?.location}.</p>

      <label className="block max-w-lg space-y-2 text-sm">
        <span className="flex items-center justify-between gap-3">
          <span className="font-medium">Include IPs with risk &gt;=</span>
          <output aria-live="polite">{minScore}</output>
        </span>
        <input
          className="w-full accent-cyan-600"
          max={100}
          min={0}
          onChange={(event) => setMinScore(Number(event.currentTarget.value))}
          step={5}
          type="range"
          value={minScore}
          disabled={disabled}
        />
      </label>

      {availableCandidates.length === 0 ? (
        <EmptyState message="No IPs meet this risk score." />
      ) : (
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Override blocked IPs</legend>
          <div className="max-h-52 space-y-1 overflow-y-auto rounded border border-slate-200 p-3">
            {availableCandidates.map((candidate) => (
              <label className="flex items-center gap-2 text-sm" key={candidate.ip}>
                <input
                  checked={!excludedIPs.has(candidate.ip)}
                  onChange={() => toggleCandidate(candidate.ip)}
                  disabled={disabled}
                  type="checkbox"
                />
                <code className="break-all">{candidate.ip}</code>
                <span className="text-slate-600">score {candidate.score}</span>
                {candidate.manual && <span className="rounded bg-slate-100 px-2 py-0.5 text-xs">Manually added</span>}
              </label>
            ))}
          </div>
        </fieldset>
      )}

      <p className="rounded-full bg-slate-100 px-3 py-1 text-sm" role="status">
        {selectedCandidates.length} IPs will be blocked
      </p>

      {selectedCandidates.length === 0 ? (
        <EmptyState message="No IPs selected to block." />
      ) : (
        <>
          <div className="grid grid-cols-[auto_minmax(0,1fr)] overflow-x-auto rounded border border-slate-200 bg-slate-50 text-sm">
            <pre aria-hidden="true" className="select-none border-r border-slate-200 px-3 py-3 text-right font-mono text-slate-500">
              {lines.map((_, index) => index + 1).join('\n')}
            </pre>
            <pre aria-label="Generated blocklist" className="overflow-x-auto px-3 py-3 font-mono" ref={outputRef}>
              {output}
            </pre>
          </div>
          <div className="flex flex-wrap gap-2">
            <button className="rounded border border-slate-300 px-3 py-2 text-sm" onClick={() => void handleCopyAll()} type="button">Copy all</button>
            <button className="rounded border border-slate-300 px-3 py-2 text-sm" onClick={handleDownload} type="button">Download .txt</button>
            <button className="rounded border border-slate-300 px-3 py-2 text-sm" onClick={handleSelectAll} type="button">Select all</button>
          </div>
        </>
      )}
      <p aria-live="polite" className="sr-only" role="status">{announcement}</p>
    </section>
  );
}
