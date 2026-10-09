import { WEIGHTS as CONTRACT_WEIGHTS } from '../contracts';

export const WEIGHTS = Object.freeze({ ...CONTRACT_WEIGHTS });

export const RATING_CUTOFFS = Object.freeze({ CRITICAL: 80, HIGH: 60, MEDIUM: 30 });

export const MAX_LINE_LENGTH = 8192;

export const BRUTE_FORCE = Object.freeze({ THRESHOLD: 5, WINDOW_SEC: 60 });

export const TIMELINE_BUCKET_MS = 300000;

export const PRIVATE_IP_RANGES: readonly string[] = Object.freeze([
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '100.64.0.0/10',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
]);
