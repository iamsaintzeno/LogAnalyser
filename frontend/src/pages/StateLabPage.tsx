import { Dashboard } from './Dashboard';
import { UploadPage } from './UploadPage';
import { stateLabFixtures } from '../mock/stateLabFixtures';
import { useAnalyzerStore } from '../store/useAnalyzerStore';

const FIXTURE_BUTTONS = [
  { key: 'clean', label: '0 threats (clean log)' },
  { key: 'oneAttacker', label: '1 attacker' },
  { key: 'manyAttackers', label: '5,000 attackers' },
  { key: 'timelineSingle', label: 'Timeline: single bucket' },
  { key: 'thirtyDayTimeline', label: 'Timeline: 30-day span' },
  { key: 'ipv6Fixture', label: 'IPv6: 2001:db8::1' },
  { key: 'xssFixture', label: 'XSS strings' },
  { key: 'skippedLines', label: 'All lines skipped' },
  { key: 'timezones', label: 'Different timezone offsets' },
] as const;

export function StateLabPage() {
  const status = useAnalyzerStore((state) => state.status);
  const result = useAnalyzerStore((state) => state.result);
  const setResult = useAnalyzerStore((state) => state.setResult);
  const setError = useAnalyzerStore((state) => state.setError);

  function loadFixture(key: keyof typeof stateLabFixtures) {
    useAnalyzerStore.getState().resetFilters();
    useAnalyzerStore.setState({ blocklist: [] });
    setResult(stateLabFixtures[key]);
    if (key === 'skippedLines') {
      setError('No valid log lines found. Is this an Apache/Nginx access log?');
    }
  }

  return (
    <div className="space-y-6">
      <section aria-labelledby="state-lab-title" className="space-y-3 rounded-lg border border-violet-300 bg-violet-50 p-4">
        <h1 className="text-2xl font-semibold" id="state-lab-title">State Lab (development only)</h1>
        <p className="text-sm">Load a fixture into the analyzer store to check how the app handles unusual data.</p>
        <div className="flex flex-wrap gap-2">
          {FIXTURE_BUTTONS.map(({ key, label }) => (
            <button
              className="rounded border border-violet-400 bg-white px-3 py-2 text-sm hover:bg-violet-100"
              key={key}
              onClick={() => loadFixture(key)}
              type="button"
            >
              {label}
            </button>
          ))}
        </div>
        <p className="text-sm text-slate-700">For XSS and IPv6 fixtures, open an attacker row to inspect the detail view.</p>
      </section>

      {status === 'done' && result ? <Dashboard /> : status === 'error' ? <UploadPage /> : (
        <p className="text-sm text-slate-600">Choose a fixture above to show its screen.</p>
      )}
    </div>
  );
}
