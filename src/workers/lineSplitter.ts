export const MAX_LINE_LENGTH = 8_192;

export interface LineSplitterState {
  carry: string;
  discardingLine: boolean;
}

export interface LineSplitResult {
  lines: string[];
  lineOffsets: number[];
  state: LineSplitterState;
  skipped: number;
}

export interface FinishedLines {
  lines: string[];
  lineOffsets: number[];
  skipped: number;
}

export function splitChunk(
  chunk: string,
  state: LineSplitterState = { carry: '', discardingLine: false },
  maxLineLength = MAX_LINE_LENGTH,
): LineSplitResult {
  const lines: string[] = [];
  const lineOffsets: number[] = [];
  let skipped = 0;
  let completedLineCount = 0;
  let carry = state.carry;
  let discardingLine = state.discardingLine;
  let cursor = 0;
  let newlineIndex = chunk.indexOf('\n', cursor);

  while (newlineIndex !== -1) {
    const segment = chunk.slice(cursor, newlineIndex);

    if (discardingLine) {
      skipped += 1;
      discardingLine = false;
    } else {
      let line = carry + segment;
      if (line.endsWith('\r')) line = line.slice(0, -1);

      if (line.length > maxLineLength) {
        skipped += 1;
      } else {
        lines.push(line);
        lineOffsets.push(completedLineCount);
      }
    }

    completedLineCount += 1;
    carry = '';
    cursor = newlineIndex + 1;
    newlineIndex = chunk.indexOf('\n', cursor);
  }

  const remainder = chunk.slice(cursor);

  if (!discardingLine) {
    carry += remainder;
    const possibleCarriageReturn = carry.endsWith('\r') ? 1 : 0;
    if (carry.length - possibleCarriageReturn > maxLineLength) {
      carry = '';
      discardingLine = true;
    }
  }

  return {
    lines,
    lineOffsets,
    state: { carry, discardingLine },
    skipped,
  };
}

export function finishLines(
  state: LineSplitterState,
  maxLineLength = MAX_LINE_LENGTH,
): FinishedLines {
  if (state.discardingLine) return { lines: [], lineOffsets: [], skipped: 1 };
  if (state.carry.length === 0) return { lines: [], lineOffsets: [], skipped: 0 };

  if (state.carry.length > maxLineLength) return { lines: [], lineOffsets: [], skipped: 1 };

  return { lines: [state.carry], lineOffsets: [0], skipped: 0 };
}
