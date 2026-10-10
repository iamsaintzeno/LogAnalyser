import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createAnalyzer } from '../src/engine/analyze.ts';
import { parseLine } from '../src/engine/parseLine.ts';
import { generateMockLog as generateCore } from '../src/lib/mockLogCore.mjs';
import { generateMockLog as generateBrowser } from '../src/lib/mockLog.ts';

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

describe('mock log generator', () => {
  it('produces exactly 5,000 sorted lines with the required truth counts', () => {
    const { text, truth } = generateCore();
    const lines = text.split('\n');
    const counts = truth.reduce<Record<string, number>>((result, item) => {
      result[item.label] = (result[item.label] ?? 0) + 1;
      return result;
    }, {});
    const seconds = lines.flatMap((line, index) => {
      if (truth[index]?.malformed) return [];
      const match = /^\S+ \S+ \S+ \[(\d{2})\/Oct\/2026:(\d{2}):(\d{2}):(\d{2}) \+0000\]/.exec(line);
      expect(match).not.toBeNull();
      return [Number(match![2]) * 3600 + Number(match![3]) * 60 + Number(match![4])];
    });

    expect(lines).toHaveLength(5_000);
    expect(truth).toHaveLength(5_000);
    expect(counts.NORMAL).toBe(4_000);
    expect(THREAT_LABELS.reduce((sum, label) => sum + (counts[label] ?? 0), 0)).toBe(1_000);
    expect(seconds).toEqual([...seconds].sort((left, right) => left - right));
    expect(truth.filter((item) => item.malformed)).toHaveLength(5);
    expect(truth.filter((item) => item.also === 'SCANNER_UA')).toHaveLength(150);
  });

  it('places exactly 450 attacks in the 03:10-03:25 spike and includes required noise', () => {
    const { text, truth } = generateCore();
    const lines = text.split('\n');
    const inSpike = truth.filter((item) => {
      if (item.label === 'NORMAL' || item.malformed) return false;
      const match = /\[(\d{2})\/Oct\/2026:(\d{2}):(\d{2}):(\d{2}) \+0000\]/.exec(lines[item.line - 1]);
      if (!match) return false;
      const seconds = Number(match[2]) * 3600 + Number(match[3]) * 60 + Number(match[4]);
      return seconds >= 3 * 3600 + 10 * 60 && seconds < 3 * 3600 + 25 * 60;
    });
    const sqlmapLines = lines.filter((line) => line.includes('sqlmap/1.7.2#stable'));
    const successfulNormalLogins = lines.filter((line, index) => (
      truth[index]?.label === 'NORMAL'
      && line.includes('"POST /wp-login.php HTTP/1.1" 302 ')
    ));

    expect(inSpike).toHaveLength(450);
    expect(lines.filter((line) => line.includes('HTTP/2.0')).length).toBe(15);
    expect(lines.filter((line) => line.startsWith('2001:db8::')).length).toBe(10);
    expect(sqlmapLines).toHaveLength(150);
    expect(successfulNormalLogins).toHaveLength(3);
  });

  it('is deterministic and the Node and browser entry points share identical output', () => {
    const core = generateCore(987654321);
    const repeated = generateCore(987654321);
    const browser = generateBrowser(987654321);

    expect(sha256(core.text)).toBe(sha256(repeated.text));
    expect(sha256(core.text)).toBe(sha256(browser.text));
    expect(core.truth).toEqual(repeated.truth);
    expect(core.truth).toEqual(browser.truth);
  });

  it('parses every non-malformed normal line and keeps malformed noise unparseable', () => {
    const { text, truth } = generateCore();
    const lines = text.split('\n');
    for (const item of truth) {
      if (item.label !== 'NORMAL') continue;
      const parsed = parseLine(lines[item.line - 1], item.line);
      if (item.malformed) expect(parsed).toBeNull();
      else expect(parsed, `normal line ${item.line}`).not.toBeNull();
    }
  });

  it('meets the engine recall and false-positive targets and prints its confusion matrix', () => {
    const { text, truth } = generateCore();
    const lines = text.split('\n');
    const entries = lines.flatMap((line, index) => {
      const entry = parseLine(line, index + 1);
      return entry ? [entry] : [];
    });
    const analyzer = createAnalyzer();
    analyzer.push(entries);
    const result = analyzer.finish({
      fileName: 'sample-nginx-5000.log',
      fileSize: new TextEncoder().encode(text).byteLength,
      totalLines: lines.length,
      parsedLines: entries.length,
      skippedLines: lines.length - entries.length,
    });
    expect(result.session.timeline.every((bucket) => (
      bucket.total === Object.values(bucket.byType).reduce((sum, count) => sum + count, 0)
    ))).toBe(true);
    expect(result.session.timeline.reduce((sum, bucket) => sum + bucket.total, 0)).toBe(result.events.length);
    const eventsByLine = new Map<number, Set<string>>();
    for (const event of result.events) {
      const types = eventsByLine.get(event.entryId) ?? new Set<string>();
      types.add(event.type);
      eventsByLine.set(event.entryId, types);
    }

    const matrix = {
      attackDetected: 0,
      attackMissed: 0,
      normalFalsePositive: 0,
      normalTrueNegative: 0,
    };
    const byLabel: Record<string, { detected: number; missed: number }> = {};
    const examples: Record<string, string[]> = {};
    for (const item of truth) {
      const detected = eventsByLine.get(item.line) ?? new Set<string>();
      if (item.label === 'NORMAL') {
        if (detected.size > 0) matrix.normalFalsePositive += 1;
        else matrix.normalTrueNegative += 1;
      } else if (detected.has(item.label) && (!item.also || detected.has(item.also))) {
        matrix.attackDetected += 1;
        byLabel[item.label] ??= { detected: 0, missed: 0 };
        byLabel[item.label].detected += 1;
      } else {
        matrix.attackMissed += 1;
        byLabel[item.label] ??= { detected: 0, missed: 0 };
        byLabel[item.label].missed += 1;
        examples[item.label] ??= [];
        if (examples[item.label].length < 3) examples[item.label].push(lines[item.line - 1]);
      }
    }

    console.log('Mock log confusion matrix:', matrix, byLabel, examples);
    expect(matrix.attackDetected / (matrix.attackDetected + matrix.attackMissed)).toBeGreaterThanOrEqual(0.95);
    expect(matrix.normalFalsePositive / 4_000).toBeLessThanOrEqual(0.01);
    expect(result.session.summaries[0]?.ip).toMatch(/^203\.0\.113\.(10|11|12)$/);
    expect(['CRITICAL', 'HIGH']).toContain(result.session.summaries[0]?.rating);
  });
});

const THREAT_LABELS = ['BRUTE_FORCE', 'SQLI', 'TRAVERSAL', 'SCANNER_UA', 'SENSITIVE_PROBE'] as const;
