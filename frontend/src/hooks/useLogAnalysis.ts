import { useCallback, useEffect, useRef, useState } from 'react';
import type { RuleOverride } from '../../../src/contracts/index.ts';
import { CONTRACT_VERSION, type WorkerResponse } from '../../../src/contracts/messages.ts';
import { ParserWorkerClient } from '../../../src/workers/parserWorkerClient.ts';
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
    if (useAnalyzerStore.getState().status === 'error') return;
    if (typeof Worker === 'undefined') {
      setError('Web Workers are not available in this browser.');
      return;
    }

    let client: ParserWorkerClient;
    try {
      client = new ParserWorkerClient();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Could not start the local parser.');
      return;
    }
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
        if (response.code === 'CANCELLED') reset();
        else setError(response.message);
      }
    });
    const unsubscribeError = client.subscribeError((message) => {
      activeRequestRef.current = null;
      setReady(false);
      setError(`Parser worker failed: ${message}`);
    });

    return () => {
      unsubscribe();
      unsubscribeError();
      if (activeRequestRef.current) client.cancel(activeRequestRef.current);
      activeRequestRef.current = null;
      client.terminate();
      clientRef.current = null;
    };
  }, [reset, setError, setProgress, setResult]);

  const begin = useCallback((sendRequest: (
    client: ParserWorkerClient,
    overrides: RuleOverride[],
    allowIps: string[],
  ) => string) => {
    const client = clientRef.current;
    if (!client || !ready) {
      setError('The local parser is not ready yet. Please try again.');
      return;
    }

    if (activeRequestRef.current) client.cancel(activeRequestRef.current);
    activeRequestRef.current = null;
    setSkipped(0);
    startParsing();
    const { ruleOverrides, allowIps } = useAnalyzerStore.getState();
    try {
      activeRequestRef.current = sendRequest(client, ruleOverrides, allowIps);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Could not start local analysis.');
    }
  }, [ready, setError, startParsing]);

  const analyzeFile = useCallback((file: File) => {
    begin((client, overrides, allowIps) => client.analyzeFile(file, overrides, allowIps));
  }, [begin]);

  const analyzeText = useCallback((text: string, fileName: string) => {
    begin((client, overrides, allowIps) => client.analyzeText(text, fileName, overrides, allowIps));
  }, [begin]);

  const cancel = useCallback(() => {
    const requestId = activeRequestRef.current;
    activeRequestRef.current = null;
    if (requestId) clientRef.current?.cancel(requestId);
    setSkipped(0);
    reset();
  }, [reset]);

  return { analyzeFile, analyzeText, cancel, ready, skipped };
}
