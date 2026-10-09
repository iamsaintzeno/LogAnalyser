import { generateMockLog as generate } from './mockLogCore.mjs';
import type { ThreatType } from '../contracts/index.ts';

export type MockLogLabel = 'NORMAL' | ThreatType;

export interface MockLogTruth {
  line: number;
  label: MockLogLabel;
  also?: ThreatType;
  malformed?: true;
}

export interface MockLog {
  text: string;
  truth: MockLogTruth[];
}

export function generateMockLog(seed = 20261009): MockLog {
  return generate(seed);
}
