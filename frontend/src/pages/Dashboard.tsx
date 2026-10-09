import { useAnalyzerStore } from '../store/useAnalyzerStore';
import { SummaryCards } from '../components/dashboard/SummaryCards';
import { AttackTimeline } from '../components/dashboard/AttackTimeline';
import { AttackerTable } from '../components/dashboard/AttackerTable';
import { FilterBar } from '../components/dashboard/FilterBar';
import { selectThreatTypeCounts, useFilteredData } from '../store/selectors';

export function Dashboard() {
  const result = useAnalyzerStore((state) => state.result);
  const { summaries, timeline } = useFilteredData();

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
      <h1 className="text-2xl font-semibold">Dashboard</h1>
      {result && <SummaryCards result={result} />}
      <FilterBar
        firstTimestamp={firstTimestamp}
        lastTimestamp={lastTimestamp}
        shownIPs={summaries.length}
        totalIPs={result.session.summaries.length}
        typeCounts={selectThreatTypeCounts(result.events)}
      />
      {result && (
        <section className="space-y-3">
          <h2 className="text-xl font-semibold">Attack Timeline</h2>
          <AttackTimeline buckets={timeline} />
        </section>
      )}
      {result && (
        <section className="space-y-3">
          <h2 className="text-xl font-semibold">Attackers</h2>
          <AttackerTable rows={summaries} onRowClick={() => {}} />
        </section>
      )}
      <p>Analysis results will be shown here.</p>
      <p>
        Mock data includes 12 attacker summaries, 60 threat events, 120 flagged log entries,
        and 48 five-minute timeline buckets with one spike.
      </p>
      <p role="status">
        {result ? `Loaded ${result.events.length} mock threat events.` : 'No result loaded.'}
      </p>
    </section>
  );
}
