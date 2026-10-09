import { useAnalyzerStore } from '../store/useAnalyzerStore';
import { SummaryCards } from '../components/dashboard/SummaryCards';
import { AttackTimeline } from '../components/dashboard/AttackTimeline';
import { AttackerTable } from '../components/dashboard/AttackerTable';

export function Dashboard() {
  const result = useAnalyzerStore((state) => state.result);

  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-semibold">Dashboard</h1>
      {result && <SummaryCards result={result} />}
      {result && (
        <section className="space-y-3">
          <h2 className="text-xl font-semibold">Attack Timeline</h2>
          <AttackTimeline buckets={result.session.timeline} />
        </section>
      )}
      {result && (
        <section className="space-y-3">
          <h2 className="text-xl font-semibold">Attackers</h2>
          <AttackerTable rows={result.session.summaries} onRowClick={() => {}} />
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
