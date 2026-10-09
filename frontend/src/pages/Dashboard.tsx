import { useState } from 'react';
import { useAnalyzerStore } from '../store/useAnalyzerStore';
import { SummaryCards } from '../components/dashboard/SummaryCards';
import { AttackTimeline } from '../components/dashboard/AttackTimeline';
import { AttackerTable } from '../components/dashboard/AttackerTable';
import { FilterBar } from '../components/dashboard/FilterBar';
import { IpDetailModal } from '../components/dashboard/IpDetailModal';
import { BlocklistPanel } from '../components/dashboard/BlocklistPanel';
import { selectThreatTypeCounts, useFilteredData } from '../store/selectors';

export function Dashboard() {
  const status = useAnalyzerStore((state) => state.status);
  const result = useAnalyzerStore((state) => state.result);
  const { summaries, timeline } = useFilteredData();
  const [selectedIP, setSelectedIP] = useState<string | null>(null);

  if (!result) {
    return (
      <section className="space-y-4">
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p>No analysis result is available.</p>
      </section>
    );
  }

  const eventTimes = result.events.map((event) => event.ts);
  const firstTimestamp = result.session.timeline[0]?.t ?? Math.min(...eventTimes, result.session.createdAt);
  const lastTimestamp = result.session.timeline.length > 0
    ? result.session.timeline[result.session.timeline.length - 1].t + 5 * 60_000
    : Math.max(...eventTimes, result.session.createdAt);

  return (
    <section className="space-y-4">
      <h1 className="print-hide text-2xl font-semibold">Dashboard</h1>
      <p className="print-hide text-sm text-slate-600">Times shown in {Intl.DateTimeFormat().resolvedOptions().timeZone || 'your local timezone'}.</p>
      {result.session.threatCount === 0 && (
        <div className="print-hide rounded-lg border border-green-300 bg-green-50 p-5 text-green-950" role="status">
          <h2 className="text-xl font-semibold">No attacks detected</h2>
          <p className="mt-1">This log has no flagged threats. You can still review the log summary below.</p>
        </div>
      )}
      {result && <div className="print-summary"><SummaryCards result={result} /></div>}
      <div className="print-hide">
        <FilterBar
          firstTimestamp={firstTimestamp}
          lastTimestamp={lastTimestamp}
          shownIPs={summaries.length}
          totalIPs={result.session.summaries.length}
          typeCounts={selectThreatTypeCounts(result.events)}
        />
      </div>
      {result && (
        <section className="print-hide space-y-3">
          <h2 className="text-xl font-semibold">Attack Timeline</h2>
          <AttackTimeline buckets={timeline} />
        </section>
      )}
      {result && (
        <section className="print-attackers space-y-3">
          <h2 className="text-xl font-semibold">Attackers</h2>
          <AttackerTable loading={status === 'parsing'} rows={summaries} onRowClick={setSelectedIP} />
        </section>
      )}
      {result && <div className="print-blocklist"><BlocklistPanel disabled={result.session.threatCount === 0} /></div>}
      {selectedIP && <IpDetailModal ip={selectedIP} onClose={() => setSelectedIP(null)} />}
      <p className="print-hide">Analysis results will be shown here.</p>
      <p className="print-hide">
        Mock data includes 12 attacker summaries, 60 threat events, 120 flagged log entries,
        and 48 five-minute timeline buckets with one spike.
      </p>
      <p className="print-hide" role="status">
        {result ? `Loaded ${result.events.length} mock threat events.` : 'No result loaded.'}
      </p>
    </section>
  );
}
