import { beforeEach, describe, expect, it } from 'vitest';
import type { AttackerIPSummary } from '../src/contracts';
import { selectFilteredSummaries } from '../../src/store/selectors';
import { useAnalyzerStore } from '../src/store/useAnalyzerStore';
import { mockResult } from '../src/mock/mockResult';

describe('minimum risk score filter', () => {
  beforeEach(() => {
    useAnalyzerStore.getState().resetFilters();
  });

  it('excludes scores below 70, keeps 70 and above, then returns all when reset to 0', () => {
    const attackers: AttackerIPSummary[] = mockResult.session.summaries.slice(0, 3).map((attacker, index) => ({
      ...attacker,
      ip: `198.51.100.${index + 1}`,
      score: [69, 70, 88][index],
    }));

    useAnalyzerStore.getState().setFilters({ minScore: 70 });
    const filtered = selectFilteredSummaries(attackers, useAnalyzerStore.getState().filters);

    expect(filtered.map((attacker) => attacker.score)).toEqual([70, 88]);
    expect(filtered.some((attacker) => attacker.score < 70)).toBe(false);
    expect(filtered.some((attacker) => attacker.score === 70)).toBe(true);
    expect(filtered.every((attacker) => attacker.score >= 70)).toBe(true);

    useAnalyzerStore.getState().resetFilters();
    expect(useAnalyzerStore.getState().filters.minScore).toBe(0);
    const resetResults = selectFilteredSummaries(attackers, useAnalyzerStore.getState().filters);
    expect(resetResults).toEqual(attackers);
  });
});
