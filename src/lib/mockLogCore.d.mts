import type { ThreatType } from '../contracts/index.ts';

export interface MockLogCoreTruth {
  line: number;
  label: 'NORMAL' | ThreatType;
  also?: ThreatType;
  malformed?: true;
}

export interface MockLogCoreResult {
  text: string;
  truth: MockLogCoreTruth[];
}

export function generateMockLog(seed?: number): MockLogCoreResult;
