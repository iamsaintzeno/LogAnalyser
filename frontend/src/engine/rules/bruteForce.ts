import type { LogEntry } from '../../contracts';

export const BRUTE_FORCE_WINDOW_MS = 5 * 60_000;
export const BRUTE_FORCE_MIN_REQUESTS = 10;

/** Returns every failed POST entry that belongs to a qualifying IP/path window. */
export function findBruteForceEntries(entries: LogEntry[]): Set<LogEntry> {
  const groups = new Map<string, Array<{ entry: LogEntry; index: number }>>();
  entries.forEach((entry, index) => {
    if (entry.method !== 'POST' || (entry.status !== 401 && entry.status !== 403)) return;
    const key = JSON.stringify([entry.ip, entry.path]);
    const group = groups.get(key) ?? [];
    group.push({ entry, index });
    groups.set(key, group);
  });

  const flagged = new Set<LogEntry>();
  for (const group of groups.values()) {
    group.sort((left, right) => left.entry.ts - right.entry.ts || left.index - right.index);
    let firstInWindow = 0;
    for (let lastInWindow = 0; lastInWindow < group.length; lastInWindow += 1) {
      while (
        group[lastInWindow].entry.ts - group[firstInWindow].entry.ts > BRUTE_FORCE_WINDOW_MS
      ) firstInWindow += 1;

      if (lastInWindow - firstInWindow + 1 < BRUTE_FORCE_MIN_REQUESTS) continue;
      for (let index = firstInWindow; index <= lastInWindow; index += 1) {
        flagged.add(group[index].entry);
      }
    }
  }
  return flagged;
}
