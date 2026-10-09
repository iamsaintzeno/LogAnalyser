import { useEffect, useRef, useState } from 'react';
import { LogDropzone } from '../components/upload/LogDropzone';
import { mockResult } from '../mock/mockResult';
import { useAnalyzerStore } from '../store/useAnalyzerStore';
import { useLogAnalysis } from '../hooks/useLogAnalysis';

const SIMULATED_TOTAL_BYTES = 3000;
const SIMULATION_DURATION_MS = 3000;

function ParseProgress({ onCancel, skipped }: { onCancel: () => void; skipped: number }) {
  const progress = useAnalyzerStore((state) => state.progress);
  const [announcedProgress, setAnnouncedProgress] = useState(progress);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const startedAt = useRef(Date.now());
  const hasTotal = progress.totalBytes > 0;
  const percent = hasTotal
    ? Math.min(100, Math.max(0, Math.round((progress.bytesRead / progress.totalBytes) * 100)))
    : 0;
  const announcedPercent = announcedProgress.totalBytes > 0
    ? Math.min(100, Math.max(0, Math.round((announcedProgress.bytesRead / announcedProgress.totalBytes) * 100)))
    : 0;

  useEffect(() => {
    startedAt.current = Date.now();
    const interval = window.setInterval(() => {
      setAnnouncedProgress(useAnalyzerStore.getState().progress);
      setElapsedSeconds(Math.floor((Date.now() - startedAt.current) / 1000));
    }, 1000);

    return () => window.clearInterval(interval);
  }, []);

  return (
    <section aria-labelledby="parse-heading" className="space-y-4">
      <h1 className="text-2xl font-semibold" id="parse-heading">Analyzing your log locally</h1>
      <div
        aria-label="Log analysis progress"
        aria-valuemax={100}
        aria-valuemin={0}
        aria-valuenow={hasTotal ? percent : undefined}
        aria-valuetext={hasTotal ? `${percent}%` : 'Progress is indeterminate'}
        className="h-3 overflow-hidden rounded-full bg-slate-200"
        role="progressbar"
      >
        {hasTotal ? (
          <div className="h-full bg-cyan-500 transition-[width]" style={{ width: `${percent}%` }} />
        ) : (
          <div className="h-full w-1/3 animate-pulse bg-cyan-500" />
        )}
      </div>
      <p aria-live="polite" className="text-sm">
        Parsed {announcedProgress.lines} lines - {announcedPercent}%
      </p>
      <p className="text-sm text-slate-600">Skipped {skipped} lines</p>
      <p className="text-sm text-slate-600">Elapsed {elapsedSeconds} seconds</p>
      <button
        className="rounded-md border border-slate-300 px-4 py-2 font-medium hover:bg-slate-50"
        onClick={onCancel}
        type="button"
      >
        Cancel
      </button>
    </section>
  );
}

function ErrorMessage({ message, onTryAgain }: { message: string; onTryAgain: () => void }) {
  return (
    <section aria-labelledby="error-heading" className="space-y-4">
      <h1 className="text-2xl font-semibold" id="error-heading">Could not analyze this file</h1>
      <p role="alert">{message}</p>
      <p className="text-sm text-slate-600">
        Tip: Supported: Apache/Nginx access logs in Common or Combined format
      </p>
      <button
        className="rounded-md border border-slate-300 px-4 py-2 font-medium hover:bg-slate-50"
        onClick={onTryAgain}
        type="button"
      >
        Try another file
      </button>
    </section>
  );
}

function IdleUpload({
  onSimulateParsing,
  onFile,
  parserReady,
}: {
  onSimulateParsing: () => void;
  onFile: (file: File) => void;
  parserReady: boolean;
}) {
  const setResult = useAnalyzerStore((state) => state.setResult);

  return (
    <section className="space-y-8">
      <div className="space-y-3">
        <h1 className="text-3xl font-semibold">Find out who attacked your website - without uploading your logs</h1>
        <ol aria-label="How it works" className="flex flex-wrap items-center gap-2 text-sm">
          <li>Upload</li><li aria-hidden="true">→</li>
          <li>Local analysis</li><li aria-hidden="true">→</li>
          <li>Blocklist</li>
        </ol>
      </div>

      <div className="space-y-3">
        <h2 className="text-xl font-semibold">What it detects</h2>
        <ul className="list-inside list-disc space-y-1">
          <li><strong>Brute force:</strong> repeated sign-in attempts.</li>
          <li><strong>SQL injection:</strong> a query containing <code>UNION SELECT</code>.</li>
          <li><strong>Path traversal:</strong> a request for <code>../../etc/passwd</code>.</li>
          <li><strong>Sensitive file probes:</strong> a request for <code>/.env</code>.</li>
        </ul>
      </div>

      <LogDropzone
        disabled={!parserReady}
        onFile={onFile}
        onDemo={onSimulateParsing}
      />

      {import.meta.env.DEV && (
        <button
          className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium hover:bg-slate-50"
          onClick={onSimulateParsing}
          type="button"
        >
          Simulate parsing
        </button>
      )}

      {!parserReady && <p className="text-sm text-slate-600" role="status">Starting the local parser…</p>}

      <button
        className="rounded-md border border-slate-300 px-4 py-2 font-medium hover:bg-slate-50"
        onClick={() => setResult(mockResult)}
        type="button"
      >
        Load mock result
      </button>
    </section>
  );
}

export function UploadPage() {
  const { analyzeFile, cancel, ready: parserReady, skipped } = useLogAnalysis();
  const status = useAnalyzerStore((state) => state.status);
  const error = useAnalyzerStore((state) => state.error);
  const reset = useAnalyzerStore((state) => state.reset);
  const startParsing = useAnalyzerStore((state) => state.startParsing);
  const setProgress = useAnalyzerStore((state) => state.setProgress);
  const setResult = useAnalyzerStore((state) => state.setResult);
  const timer = useRef<number | null>(null);

  useEffect(() => () => {
    if (timer.current !== null) window.clearInterval(timer.current);
  }, []);

  function simulateParsing() {
    if (timer.current !== null) window.clearInterval(timer.current);
    startParsing('mock-access.log', SIMULATED_TOTAL_BYTES);
    const startedAt = Date.now();

    timer.current = window.setInterval(() => {
      const elapsed = Math.min(Date.now() - startedAt, SIMULATION_DURATION_MS);
      const fraction = elapsed / SIMULATION_DURATION_MS;
      setProgress({
        bytesRead: Math.round(SIMULATED_TOTAL_BYTES * fraction),
        totalBytes: SIMULATED_TOTAL_BYTES,
        lines: Math.round(mockResult.session.parsedLines * fraction),
      });

      if (elapsed >= SIMULATION_DURATION_MS) {
        if (timer.current !== null) window.clearInterval(timer.current);
        timer.current = null;
        setResult(mockResult);
      }
    }, 100);
  }

  function cancelParsing() {
    if (timer.current !== null) window.clearInterval(timer.current);
    timer.current = null;
    reset();
  }

  if (status === 'parsing') {
    return <ParseProgress onCancel={() => { cancelParsing(); cancel(); }} skipped={skipped} />;
  }

  if (status === 'error') {
    return <ErrorMessage message={error ?? 'An unknown error occurred.'} onTryAgain={reset} />;
  }

  if (status === 'done') return null;

  return <IdleUpload onFile={analyzeFile} onSimulateParsing={simulateParsing} parserReady={parserReady} />;
}
