import type { LogEntry, ParseResult, RuleOverride } from '../contracts/index.ts';
import {
  CONTRACT_VERSION,
  type WorkerRequest,
  type WorkerResponse,
} from '../contracts/messages.ts';
import {
  finishLines,
  splitChunk,
  type LineSplitterState,
} from './lineSplitter.ts';

// The engine is injected until its production exports are available.
const MAX_FILE_SIZE = 200 * 1024 * 1024;
const BATCH_SIZE = 2_000;
const YIELD_EVERY_LINES = 20_000;
const PROGRESS_INTERVAL_MS = 100;

export interface AnalysisMetadata {
  fileName: string;
  fileSize: number;
  totalLines: number;
  skippedLines: number;
  startedAt: number;
}

export interface Analyzer {
  push(batch: LogEntry[]): void;
  finish(metadata: AnalysisMetadata): ParseResult;
}

export interface ParserEngine {
  parseLine(line: string, lineNo: number): LogEntry | null;
  createAnalyzer(options: { overrides: RuleOverride[]; allowIps: string[] }): Analyzer;
}

export interface ParserWorkerScope {
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  postMessage(message: WorkerResponse): void;
}

interface ActiveAnalysis {
  requestId: string;
  cancelled: boolean;
  terminalSent: boolean;
  reader?: ReadableStreamDefaultReader<Uint8Array>;
}

interface AnalysisInput {
  stream: ReadableStream<Uint8Array>;
  fileName: string;
  fileSize: number;
  overrides: RuleOverride[];
  allowIps: string[];
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function attachParserWorker(scope: ParserWorkerScope, engine: ParserEngine): void {
  let active: ActiveAnalysis | undefined;
  let taskTail = Promise.resolve();

  const postError = (
    analysis: ActiveAnalysis,
    code: Extract<WorkerResponse, { type: 'ERROR' }>['code'],
    message: string,
  ): void => {
    if (analysis.terminalSent) return;
    analysis.terminalSent = true;
    scope.postMessage({ type: 'ERROR', requestId: analysis.requestId, code, message });
  };

  const requestCancellation = (analysis: ActiveAnalysis): void => {
    if (analysis.terminalSent || analysis.cancelled) return;
    analysis.cancelled = true;
    try {
      const cancelPromise = analysis.reader?.cancel();
      if (cancelPromise) {
        void cancelPromise.catch((error: unknown) => {
          postError(
            analysis,
            'CANCELLED',
            `Analysis cancelled; unable to stop the input stream: ${errorMessage(error)}`,
          );
        });
      }
    } catch (error) {
      postError(
        analysis,
        'CANCELLED',
        `Analysis cancelled; unable to stop the input stream: ${errorMessage(error)}`,
      );
    }
  };

  const sendProgress = (
    analysis: ActiveAnalysis,
    now: number,
    lastSentAt: number | undefined,
    bytesRead: number,
    totalBytes: number,
    lines: number,
    skipped: number,
  ): number | undefined => {
    if (
      (lastSentAt !== undefined && now - lastSentAt < PROGRESS_INTERVAL_MS)
      || analysis.cancelled
      || analysis.terminalSent
    ) {
      return lastSentAt;
    }

    scope.postMessage({
      type: 'PROGRESS',
      requestId: analysis.requestId,
      bytesRead,
      totalBytes,
      lines,
      skipped,
    });
    return now;
  };

  const runAnalysis = async (request: Exclude<WorkerRequest, { type: 'CANCEL' }>, analysis: ActiveAnalysis) => {
    const startedAt = Date.now();
    const input: AnalysisInput = request.type === 'ANALYZE_FILE'
      ? {
        stream: request.file.stream(),
        fileName: request.file.name,
        fileSize: request.file.size,
        overrides: request.overrides,
        allowIps: request.allowIps,
      }
      : {
        stream: new Blob([request.text]).stream(),
        fileName: request.fileName,
        fileSize: new TextEncoder().encode(request.text).byteLength,
        overrides: request.overrides,
        allowIps: request.allowIps,
      };

    if (input.fileSize === 0) {
      postError(analysis, 'EMPTY_FILE', 'The file is empty');
      return;
    }
    if (input.fileSize > MAX_FILE_SIZE) {
      postError(analysis, 'TOO_LARGE', 'File over 200 MB');
      return;
    }

    const reader = input.stream.getReader();
    analysis.reader = reader;
    const decoder = new TextDecoder('utf-8');
    const analyzer = engine.createAnalyzer({
      overrides: input.overrides,
      allowIps: input.allowIps,
    });
    const batch: LogEntry[] = [];
    let splitterState: LineSplitterState = { carry: '', discardingLine: false };
    let lineNo = 1;
    let totalLines = 0;
    let parsedLines = 0;
    let skippedLines = 0;
    let bytesRead = 0;
    let lastProgressAt: number | undefined;
    let isFirstChunk = true;

    const processLines = async (
      lines: string[],
      lineOffsets: number[],
      skipped: number,
    ): Promise<void> => {
      skippedLines += skipped;
      const firstLineNo = lineNo;
      const lineCount = skipped + lines.length;
      totalLines += lineCount;
      lineNo += lineCount;
      let nextYieldAt = Math.ceil(firstLineNo / YIELD_EVERY_LINES) * YIELD_EVERY_LINES;

      for (let index = 0; index < lines.length; index += 1) {
        if (analysis.cancelled) return;
        const currentLineNo = firstLineNo + lineOffsets[index];
        const entry = engine.parseLine(lines[index], currentLineNo);

        if (entry === null) {
          skippedLines += 1;
        } else {
          parsedLines += 1;
          batch.push(entry);
          if (batch.length === BATCH_SIZE) {
            analyzer.push(batch.slice());
            batch.length = 0;
          }
        }

        if (currentLineNo >= nextYieldAt) {
          await new Promise<void>((resolve) => setTimeout(resolve, 0));
          nextYieldAt += YIELD_EVERY_LINES;
        }
      }
    };

    try {
      while (true) {
        if (analysis.cancelled) {
          postError(analysis, 'CANCELLED', 'Analysis cancelled');
          return;
        }

        const { done, value } = await reader.read();
        if (analysis.cancelled) {
          postError(analysis, 'CANCELLED', 'Analysis cancelled');
          return;
        }
        if (done) break;

        bytesRead += value.byteLength;
        let text = decoder.decode(value, { stream: true });
        if (isFirstChunk) {
          isFirstChunk = false;
          if (text.startsWith('\uFEFF')) text = text.slice(1);
        }

        const split = splitChunk(text, splitterState);
        splitterState = split.state;
        await processLines(split.lines, split.lineOffsets, split.skipped);
        lastProgressAt = sendProgress(
          analysis,
          Date.now(),
          lastProgressAt,
          bytesRead,
          input.fileSize,
          totalLines,
          skippedLines,
        );
      }

      if (analysis.cancelled) {
        postError(analysis, 'CANCELLED', 'Analysis cancelled');
        return;
      }

      const finalText = decoder.decode();
      if (finalText.length > 0) {
        const split = splitChunk(finalText, splitterState);
        splitterState = split.state;
        await processLines(split.lines, split.lineOffsets, split.skipped);
      }

      const finalLines = finishLines(splitterState);
      await processLines(finalLines.lines, finalLines.lineOffsets, finalLines.skipped);
      if (analysis.cancelled) {
        postError(analysis, 'CANCELLED', 'Analysis cancelled');
        return;
      }

      if (batch.length > 0) analyzer.push(batch);

      if (parsedLines === 0) {
        postError(analysis, 'NO_VALID_LINES', 'No valid Apache/Nginx log lines found');
        return;
      }

      const result = analyzer.finish({
        fileName: input.fileName,
        fileSize: input.fileSize,
        totalLines,
        skippedLines,
        startedAt,
      });
      if (result.entries.length > 20_000) {
        throw new Error('Engine returned more than 20,000 flagged entries');
      }

      lastProgressAt = sendProgress(
        analysis,
        Date.now(),
        lastProgressAt,
        bytesRead,
        input.fileSize,
        totalLines,
        skippedLines,
      );
      if (!analysis.terminalSent) {
        scope.postMessage({ type: 'RESULT', requestId: analysis.requestId, result });
        analysis.terminalSent = true;
      }
    } finally {
      reader.releaseLock();
    }
  };

  const handleRequest = (request: WorkerRequest): void => {
    if (request.type === 'CANCEL') {
      if (active?.requestId === request.requestId) requestCancellation(active);
      return;
    }

    if (active) requestCancellation(active);

    const analysis: ActiveAnalysis = {
      requestId: request.requestId,
      cancelled: false,
      terminalSent: false,
    };
    active = analysis;
    taskTail = taskTail.then(async () => {
      try {
        if (analysis.cancelled) {
          postError(analysis, 'CANCELLED', 'Analysis cancelled');
        } else {
          await runAnalysis(request, analysis);
        }
      } catch (error) {
        if (analysis.cancelled) {
          postError(analysis, 'CANCELLED', 'Analysis cancelled');
        } else {
          postError(analysis, 'ENGINE_CRASH', errorMessage(error));
        }
      } finally {
        if (active === analysis) active = undefined;
      }
    });
  };

  scope.onmessage = (event): void => {
    handleRequest(event.data);
  };
  scope.postMessage({ type: 'READY', contractVersion: CONTRACT_VERSION });
}
