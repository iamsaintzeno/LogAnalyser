import type { LogEntry } from '../contracts';

export const MAX_LOG_LINE_LENGTH = 8_192;

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

class LineReader {
  private position = 0;
  private readonly line: string;

  constructor(line: string) {
    this.line = line;
  }

  skipSpaces(): void {
    while (this.line[this.position] === ' ') this.position += 1;
  }

  readToken(): string | null {
    this.skipSpaces();
    const start = this.position;
    while (this.position < this.line.length && this.line[this.position] !== ' ') this.position += 1;
    return this.position === start ? null : this.line.slice(start, this.position);
  }

  readBracketValue(): string | null {
    this.skipSpaces();
    if (this.line[this.position] !== '[') return null;
    const start = ++this.position;
    while (this.position < this.line.length && this.line[this.position] !== ']') this.position += 1;
    if (this.position >= this.line.length) return null;
    const value = this.line.slice(start, this.position);
    this.position += 1;
    return value;
  }

  readQuotedValue(): string | null {
    this.skipSpaces();
    if (this.line[this.position] !== '"') return null;
    this.position += 1;
    const characters: string[] = [];

    while (this.position < this.line.length) {
      const character = this.line[this.position];
      if (character === '"') {
        this.position += 1;
        return characters.join('');
      }

      if (character === '\\' && this.position + 1 < this.line.length) {
        const next = this.line[this.position + 1];
        if (next === '"' || next === '\\') {
          characters.push(next);
          this.position += 2;
          continue;
        }
      }

      characters.push(character);
      this.position += 1;
    }

    return null;
  }

  atEnd(): boolean {
    this.skipSpaces();
    return this.position === this.line.length;
  }
}

function isDigits(value: string): boolean {
  if (value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 48 || code > 57) return false;
  }
  return true;
}

function parseTimestamp(value: string): number | null {
  // Apache/Nginx time_local: 10/Oct/2000:13:55:36 -0700
  if (
    value.length !== 26 || value[2] !== '/' || value[6] !== '/' || value[11] !== ':' ||
    value[14] !== ':' || value[17] !== ':' || value[20] !== ' ' ||
    (value[21] !== '+' && value[21] !== '-')
  ) return null;

  const dayText = value.slice(0, 2);
  const monthText = value.slice(3, 6);
  const yearText = value.slice(7, 11);
  const hourText = value.slice(12, 14);
  const minuteText = value.slice(15, 17);
  const secondText = value.slice(18, 20);
  const zoneHourText = value.slice(22, 24);
  const zoneMinuteText = value.slice(24, 26);
  if (![dayText, yearText, hourText, minuteText, secondText, zoneHourText, zoneMinuteText].every(isDigits)) return null;

  const month = MONTHS.indexOf(monthText);
  if (month < 0) return null;
  const day = Number(dayText);
  const year = Number(yearText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const zoneHours = Number(zoneHourText);
  const zoneMinutes = Number(zoneMinuteText);
  if (day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59 || zoneHours > 23 || zoneMinutes > 59) return null;

  const localDate = new Date(0);
  localDate.setUTCFullYear(year, month, day);
  localDate.setUTCHours(hour, minute, second, 0);
  if (
    localDate.getUTCFullYear() !== year || localDate.getUTCMonth() !== month ||
    localDate.getUTCDate() !== day || localDate.getUTCHours() !== hour ||
    localDate.getUTCMinutes() !== minute || localDate.getUTCSeconds() !== second
  ) return null;

  const zoneSign = value[21] === '+' ? 1 : -1;
  const zoneOffset = zoneSign * (zoneHours * 60 + zoneMinutes) * 60_000;
  return localDate.getTime() - zoneOffset;
}

function parseRequest(request: string): { method: string; target: string; proto: string } | null {
  const parts: string[] = [];
  let start = 0;
  for (let index = 0; index <= request.length; index += 1) {
    if (index === request.length || request[index] === ' ') {
      if (index > start) parts.push(request.slice(start, index));
      start = index + 1;
    }
  }
  if (parts.length !== 3) return null;
  return { method: parts[0], target: parts[1], proto: parts[2] };
}

function parseNumber(value: string, allowDash: boolean): number | null {
  if (allowDash && value === '-') return 0;
  if (!isDigits(value)) return null;
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : null;
}

/** Parses one Apache/Nginx Common or Combined log line without reading or storing the source file. */
export function parseLogLine(line: string, id: number): LogEntry | null {
  // Check the limit before inspecting fields or running any pattern matching.
  if (line.length > MAX_LOG_LINE_LENGTH) return null;

  const reader = new LineReader(line);
  const ip = reader.readToken();
  const ident = reader.readToken();
  const authUser = reader.readToken();
  const timestampText = reader.readBracketValue();
  const requestText = reader.readQuotedValue();
  const statusText = reader.readToken();
  const bytesText = reader.readToken();
  if (!ip || !ident || !authUser || !timestampText || requestText === null || !statusText || !bytesText) return null;

  const ts = parseTimestamp(timestampText);
  const request = parseRequest(requestText);
  const status = parseNumber(statusText, false);
  const bytes = parseNumber(bytesText, true);
  if (ts === null || request === null || status === null || status < 100 || status > 599 || bytes === null) return null;

  let referer = '';
  let ua = '';
  if (!reader.atEnd()) {
    const refererText = reader.readQuotedValue();
    const uaText = reader.readQuotedValue();
    if (refererText === null || uaText === null || !reader.atEnd()) return null;
    referer = refererText;
    ua = uaText;
  }

  const queryStart = request.target.indexOf('?');
  const path = queryStart < 0 ? request.target : request.target.slice(0, queryStart);
  const query = queryStart < 0 ? '' : request.target.slice(queryStart + 1);

  return {
    id,
    ip,
    ts,
    method: request.method,
    path,
    query,
    proto: request.proto,
    status,
    bytes,
    referer,
    ua,
    raw: line,
  };
}
