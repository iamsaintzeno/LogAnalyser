import { describe, it, expect } from 'vitest';
import { scoreIp, ratingFor } from '../src/engine/score';
import type { ThreatType } from '../src/engine/types';

function bt(p: Partial<Record<ThreatType, number>>): Record<ThreatType, number> {
  return { BRUTE_FORCE: 0, SQLI: 0, TRAVERSAL: 0, SCANNER_UA: 0, SENSITIVE_PROBE: 0, ...p };
}

describe('scoreIp', () => {
  it('1 SENSITIVE_PROBE = 30 MEDIUM', () => {
    const r = scoreIp(bt({ SENSITIVE_PROBE: 1 }));
    expect(r.score).toBe(30);
    expect(r.rating).toBe('MEDIUM');
  });
  it('4 SENSITIVE_PROBE = 60 HIGH', () => {
    const r = scoreIp(bt({ SENSITIVE_PROBE: 4 }));
    expect(r.score).toBe(60);
    expect(r.rating).toBe('HIGH');
  });
  it('1 SQLI + 1 SENSITIVE = 55 MEDIUM', () => {
    const r = scoreIp(bt({ SQLI: 1, SENSITIVE_PROBE: 1 }));
    expect(r.score).toBe(55);
    expect(r.rating).toBe('MEDIUM');
  });
  it('5 BRUTE_FORCE = 32 MEDIUM', () => {
    const r = scoreIp(bt({ BRUTE_FORCE: 5 }));
    expect(r.score).toBe(32);
    expect(r.rating).toBe('MEDIUM');
  });
  it('32 SENSITIVE = 75 HIGH (diminishing returns cap)', () => {
    const r = scoreIp(bt({ SENSITIVE_PROBE: 32 }));
    expect(r.score).toBe(75);
    expect(r.rating).toBe('HIGH');
  });
  it('20 SQLI + 20 TRAVERSAL + 20 SENSITIVE + exposed = 100 CRITICAL (clamped)', () => {
    const r = scoreIp(bt({ SQLI: 20, TRAVERSAL: 20, SENSITIVE_PROBE: 20 }), { exposed: true });
    expect(r.score).toBe(100);
    expect(r.rating).toBe('CRITICAL');
  });
  it('all zeros = 0 LOW', () => {
    const r = scoreIp(bt({}));
    expect(r.score).toBe(0);
    expect(r.rating).toBe('LOW');
  });
  it('1 SCANNER_UA = 15 LOW', () => {
    const r = scoreIp(bt({ SCANNER_UA: 1 }));
    expect(r.score).toBe(15);
    expect(r.rating).toBe('LOW');
  });
  it('exposed adds 10, takeover adds 20', () => {
    expect(scoreIp(bt({ SCANNER_UA: 1 }), { exposed: true }).score).toBe(25);
    expect(scoreIp(bt({ SCANNER_UA: 1 }), { takeover: true }).score).toBe(35);
    expect(scoreIp(bt({ SCANNER_UA: 1 }), { exposed: true, takeover: true }).score).toBe(45);
  });
  it('rating boundaries 29/30/59/60/79/80', () => {
    expect(ratingFor(29)).toBe('LOW');
    expect(ratingFor(30)).toBe('MEDIUM');
    expect(ratingFor(59)).toBe('MEDIUM');
    expect(ratingFor(60)).toBe('HIGH');
    expect(ratingFor(79)).toBe('HIGH');
    expect(ratingFor(80)).toBe('CRITICAL');
  });
  it('custom weights are used', () => {
    const w = { BRUTE_FORCE: 15, SQLI: 50, TRAVERSAL: 25, SCANNER_UA: 15, SENSITIVE_PROBE: 30 };
    expect(scoreIp(bt({ SQLI: 1 }), {}, w).score).toBe(50);
  });
  it('breakdown has per-type points', () => {
    const r = scoreIp(bt({ SQLI: 1, SENSITIVE_PROBE: 4 }));
    expect(r.breakdown.SQLI).toBe(25);
    expect(r.breakdown.SENSITIVE_PROBE).toBe(60);
    expect(r.breakdown.BRUTE_FORCE).toBe(0);
  });
  it('never NaN; negative counts treated as 0', () => {
    const r = scoreIp(bt({ SQLI: -5, TRAVERSAL: NaN as unknown as number }));
    expect(r.score).toBe(0);
    expect(Number.isNaN(r.score)).toBe(false);
  });
  it('bad weight (NaN) does not produce NaN', () => {
    const w = { BRUTE_FORCE: NaN, SQLI: 25, TRAVERSAL: 25, SCANNER_UA: 15, SENSITIVE_PROBE: 30 };
    expect(Number.isNaN(scoreIp(bt({ BRUTE_FORCE: 3 }), {}, w).score)).toBe(false);
  });
});
