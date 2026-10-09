import { mockResult } from '../mock/mockResult';
import { LogDropzone } from '../components/upload/LogDropzone';
import { useAnalyzerStore } from '../store/useAnalyzerStore';

export function Upload() {
  const setResult = useAnalyzerStore((state) => state.setResult);

  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-semibold">Upload</h1>
      <LogDropzone
        onFile={() => {
          // File parsing will be connected in a later step.
        }}
        onDemo={() => setResult(mockResult)}
      />
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
