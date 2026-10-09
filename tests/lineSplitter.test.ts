import { describe, expect, it } from 'vitest';
import {
  MAX_LINE_LENGTH,
  finishLines,
  splitChunk,
} from '../src/workers/lineSplitter.ts';

const emptyState = () => ({ carry: '', discardingLine: false });

describe('line splitter', () => {
  it('joins a line split across three chunks', () => {
    const first = splitChunk('first-', emptyState());
    const second = splitChunk('second-', first.state);
    const third = splitChunk('third\nnext\n', second.state);

    expect(third.lines).toEqual(['first-second-third', 'next']);
    expect(third.skipped).toBe(0);
    expect(finishLines(third.state)).toEqual({ lines: [], lineOffsets: [], skipped: 0 });
  });

  it('handles CRLF split between chunks', () => {
    const first = splitChunk('line\r', emptyState());
    const second = splitChunk('\nnext\r\n', first.state);

    expect(second.lines).toEqual(['line', 'next']);
    expect(second.skipped).toBe(0);
    expect(finishLines(second.state)).toEqual({ lines: [], lineOffsets: [], skipped: 0 });
  });

  it('ignores empty chunks without losing the partial line', () => {
    const first = splitChunk('part', emptyState());
    const empty = splitChunk('', first.state);
    const last = splitChunk('ial\n', empty.state);

    expect(last.lines).toEqual(['partial']);
    expect(last.skipped).toBe(0);
  });

  it('returns a final line without a newline when finished', () => {
    const pending = splitChunk('last line', emptyState());

    expect(finishLines(pending.state)).toEqual({
      lines: ['last line'],
      lineOffsets: [0],
      skipped: 0,
    });
  });

  it('skips a 1 MB line while continuing to split later lines', () => {
    const hugeLine = 'x'.repeat(1_048_576);
    const result = splitChunk(`${hugeLine}\nvalid\n`);

    expect(result.lines).toEqual(['valid']);
    expect(result.skipped).toBe(1);
    expect(finishLines(result.state)).toEqual({ lines: [], lineOffsets: [], skipped: 0 });
  });

  it('accepts lines at the configured limit and skips longer final lines', () => {
    const accepted = splitChunk(`${'a'.repeat(MAX_LINE_LENGTH)}\n`);
    const pending = splitChunk('x'.repeat(MAX_LINE_LENGTH + 1), emptyState());

    expect(accepted.lines[0].length).toBe(MAX_LINE_LENGTH);
    expect(accepted.skipped).toBe(0);
    expect(finishLines(pending.state)).toEqual({ lines: [], lineOffsets: [], skipped: 1 });
  });

  it('preserves physical line numbers when an oversized line is skipped', () => {
    const result = splitChunk(`${'x'.repeat(MAX_LINE_LENGTH + 1)}\nvalid\n`);

    expect(result.lines).toEqual(['valid']);
    expect(result.lineOffsets).toEqual([1]);
    expect(result.skipped).toBe(1);
  });
});
