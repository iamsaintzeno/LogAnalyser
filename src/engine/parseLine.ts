import type { LogEntry } from './types';
import { MAX_LINE_LENGTH } from './constants';
import { isValidIp } from './ip';

// NOTE: Nginx $http_x_forwarded_for is out of scope. We only read the client IP in the first field.

const LOG_RE = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(?:(\S+) (\S+)(?: (HTTP\/\d(?:\.\d)?))?|[^"]*)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;

const TS_RE = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/;

const MONTHS: Record<string, number> = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

export function parseTimestamp(s: string): number | null {
  const m = TS_RE.exec(s);
  if (!m) return null;
  const day = Number(m[1]);
  const month = MONTHS[m[2].toLowerCase()];
  const year = Number(m[3]);
  const hh = Number(m[4]);
  const mm = Number(m[5]);
  const ss = Number(m[6]);
  const offH = Number(m[8]);
  const offM = Number(m[9]);
  if (month === undefined) return null;
  if (day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 59 || offM > 59) return null;
  const utc = Date.UTC(year, month, day, hh, mm, ss);
  // reject impossible dates like 31 Feb (Date.UTC would roll over)
  if (new Date(utc).getUTCDate() !== day) return null;
  const sign = m[7] === '-' ? -1 : 1;
  return utc - sign * (offH * 60 + offM) * 60000;
}

export function parseLine(raw: string, id: number): LogEntry | null {
  if (raw.length > MAX_LINE_LENGTH) return null;
  const line = raw.replace(/\r+$/, '');
  if (line.length === 0 || line.startsWith('#')) return null;

  const m = LOG_RE.exec(line);
  if (!m) return null;

  const ip = m[1];
  if (!isValidIp(ip)) return null;

  const ts = parseTimestamp(m[3]);
  if (ts === null) return null;

  let method = 'UNKNOWN';
  let path = '/';
  let query = '';
  if (m[4] !== undefined && m[5] !== undefined) {
    method = m[4];
    const q = m[5].indexOf('?');
    if (q === -1) {
      path = m[5];
    } else {
      path = m[5].slice(0, q);
      query = m[5].slice(q + 1);
    }
  }

  return {
    id,
    ip,
    ts,
    method,
    path,
    query,
    proto: m[6] ?? '',
    status: Number(m[7]),
    bytes: m[8] === '-' ? 0 : Number(m[8]),
    referer: m[9] === undefined || m[9] === '-' ? '' : m[9],
    ua: m[10] === undefined || m[10] === '-' ? '' : m[10],
    raw: line.slice(0, 2000),
  };
}
