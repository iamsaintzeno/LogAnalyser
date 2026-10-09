import { useCallback, useEffect, useRef, useState } from 'react';
import { CONTRACT_VERSION, type WorkerResponse } from '../contracts/messages';
import { ParserWorkerClient } from '../workers/parserWorkerClient';
import { useAnalyzerStore } from '../store/useAnalyzerStore';

export function useLogAnalysis() {
  const clientRef = useRef<ParserWorkerClient | null>(null);
  const activeRequestRef = useRef<string | null>(null);
  const [ready, setReady] = useState(false);
  const [skipped, setSkipped] = useState(0);
  const startParsing = useAnalyzerStore((state) => state.startParsing);
  const setProgress = useAnalyzerStore((state) => state.setProgress);
  const setResult = useAnalyzerStore((state) => state.setResult);
  const setError = useAnalyzerStore((state) => state.setError);
  const reset = useAnalyzerStore((state) => state.reset);

  useEffect(() => {
    if (typeof Worker === 'undefined') return;
    const client = new ParserWorkerClient();
    clientRef.current = client;
    const unsubscribe = client.subscribe((response: WorkerResponse) => {
      if (response.type === 'READY') {
        if (response.contractVersion !== CONTRACT_VERSION) {
          setReady(false);
          setError(`Parser worker contract mismatch (expected ${CONTRACT_VERSION}, received ${response.contractVersion}).`);
        } else {
          setReady(true);
        }
        return;
      }

      if (response.requestId !== activeRequestRef.current) return;
      if (response.type === 'PROGRESS') {
        setProgress({
          bytesRead: Math.min(response.bytesRead, response.totalBytes),
          totalBytes: response.totalBytes,
          lines: response.lines,
        });
        setSkipped(response.skipped);
      } else if (response.type === 'RESULT') {
        activeRequestRef.current = null;
        setSkipped(response.result.session.skippedLines);
        setResult(response.result);
      } else {
        activeRequestRef.current = null;
        if (response.code !== 'CANCELLED') setError(response.message);
      }
    });

    return () => {
      unsubscribe();
      if (activeRequestRef.current) client.cancel(activeRequestRef.current);
      activeRequestRef.current = null;
      client.terminate();
      clientRef.current = null;
    };
  }, [setError, setProgress, setResult]);

  const analyzeFile = useCallback((file: File) => {
    const client = clientRef.current;
    if (!client || !ready) {
      setError('The local parser is not ready yet. Please try again.');
      return;
    }

    if (activeRequestRef.current) client.cancel(activeRequestRef.current);
    activeRequestRef.current = null;
    setSkipped(0);
    startParsing(file.name, file.size);
    try {
      activeRequestRef.current = client.analyzeFile(file, [], []);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Could not start local analysis.');
    }
  }, [ready, setError, startParsing]);

  const cancel = useCallback(() => {
    const requestId = activeRequestRef.current;
    activeRequestRef.current = null;
    if (requestId) clientRef.current?.cancel(requestId);
    setSkipped(0);
    reset();
  }, [reset]);

  return { analyzeFile, cancel, ready, skipped };
}
