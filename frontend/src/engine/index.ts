import type { LogEntry, RuleOverride } from '../contracts';
import { analyzeEntries, type AnalysisMetadata } from './analyze';
import { parseLogLine } from './parseLine';

export interface AnalyzerMetadata {
  fileName: string;
  fileSize: number;
  totalLines: number;
  parsedLines: number;
  skippedLines: number;
  startedAt: number;
}

export interface Analyzer {
  push(batch: LogEntry[]): void;
  finish(metadata: AnalyzerMetadata): ReturnType<typeof analyzeEntries>;
}

/**
 * Adapter for the integration worker's incremental API. The local engine only
 * analyzes a complete set of entries, so batches are collected and passed to
 * the existing analyzer once. Detection and scoring remain in analyzeEntries.
 */
export function createAnalyzer(overrides: RuleOverride[], allowIps: Set<string>): Analyzer {
  if (overrides.length > 0 || allowIps.size > 0) {
    throw new Error('This analyzer does not support rule overrides or an IP allow-list yet.');
  }

  const entries: LogEntry[] = [];
  return {
    push(batch) {
      entries.push(...batch);
    },
    finish(metadata) {
      const analysisMetadata: AnalysisMetadata = {
        id: `${metadata.fileName}:${metadata.startedAt}`,
        fileName: metadata.fileName,
        fileSize: metadata.fileSize,
        totalLines: metadata.totalLines,
        createdAt: metadata.startedAt,
        durationMs: Math.max(0, Date.now() - metadata.startedAt),
      };
      return analyzeEntries(entries, analysisMetadata);
    },
  };
}

export { parseLogLine as parseLine };
