import type { RiskRating, ThreatEvent } from '../contracts';
import { WEIGHTS } from '../contracts';

export function scoreThreatEvents(events: ThreatEvent[]): number {
  let total = 0;
  for (const event of events) total += WEIGHTS[event.type];
  return Math.min(100, total);
}

export function ratingForScore(score: number): RiskRating {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}
