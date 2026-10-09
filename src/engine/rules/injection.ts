import type { LogEntry, ThreatEvent, Rule } from '../types';
import { normalizeTarget, isDoubleEncoded } from '../decode';

type Norm = ReturnType<typeof normalizeTarget>;
const cache = new WeakMap<LogEntry, Norm>();
function norm(e: LogEntry): Norm {
  let n = cache.get(e);
  if (!n) {
    n = normalizeTarget(e.path, e.query);
    cache.set(e, n);
  }
  return n;
}

// Any ONE match is an event (severity 3).
const SQLI_STRONG = /\bunion\b[\s(]{1,10}(?:all\s+)?select\b|\bselect\b.{1,60}?\bfrom\b|\b(?:or|and)\b\s+['"]?\d{1,6}['"]?\s*=\s*['"]?\d{1,6}|['"]\s*(?:or|and)\s*['"]?[\w]{1,20}['"]?\s*=|\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\b\s*\(?\s*['"]?\d|\binformation_schema\b|\bload_file\s*\(|\binto\s+(?:out|dump)file\b|;\s*(?:drop|insert|update|delete|truncate)\s|\bxp_cmdshell\b|\b(?:extractvalue|updatexml)\s*\(|\bgroup_concat\s*\(/;

// Weak signals: need 2 different ones, or 1 + HTTP 500 (severity 2).
// A quote (' or %27/%22) counts as ONE signal, so /search?q=o%27brien is not flagged.
function weakSignals(decoded: string, raw: string): number {
  let n = 0;
  if (decoded.includes("'") || /%27|%22/i.test(raw)) n++;
  if (/--\s|--$/.test(decoded)) n++;
  if (/#$/.test(decoded)) n++;
  if (/\bselect\b/.test(decoded)) n++;
  if (/\bunion\b/.test(decoded)) n++;
  if (/\bwhere\b.{0,30}=/.test(decoded)) n++;
  return n;
}

function strongLabel(m: string): string {
  if (m.startsWith('union')) return 'UNION SELECT';
  if (/^(?:sleep|benchmark|pg_sleep|waitfor)/.test(m)) return 'TIME-BASED SQLI';
  return 'SQLI';
}

export const sqliRule: Rule = {
  id: 'R2A_SQLI',
  type: 'SQLI',
  evaluate(e: LogEntry): ThreatEvent | null {
    const n = norm(e);
    const strong = SQLI_STRONG.exec(n.decoded);
    if (strong) {
      return {
        id: `${e.id}:R2A_SQLI`,
        entryId: e.id,
        ip: e.ip,
        ts: e.ts,
        type: 'SQLI',
        ruleId: 'R2A_SQLI',
        severity: 3,
        evidence: `${strongLabel(strong[0])}: ${strong[0].slice(0, 120)}`,
      };
    }
    const weak = weakSignals(n.decoded, n.raw);
    if (weak >= 2 || (weak >= 1 && e.status === 500)) {
      return {
        id: `${e.id}:R2A_SQLI`,
        entryId: e.id,
        ip: e.ip,
        ts: e.ts,
        type: 'SQLI',
        ruleId: 'R2A_SQLI',
        severity: 2,
        evidence: `SQLI weak signals x${weak}: ${n.decoded.slice(0, 100)}`,
      };
    }
    return null;
  },
};

const TRAVERSAL = /(?:\.\.\/|\.\.\\|\.\.;\/|%2e%2e[\/\\%]|\.\.%2f|\.\.%5c)/i;
const SYSFILES = /\/(?:etc\/(?:passwd|shadow|hosts|issue)|proc\/self\/\w+|proc\/version|windows\/win\.ini|boot\.ini|var\/log\/)|c:\/windows|\/\.ssh\/|\/root\//i;

export const traversalRule: Rule = {
  id: 'R2B_TRAVERSAL',
  type: 'TRAVERSAL',
  evaluate(e: LogEntry): ThreatEvent | null {
    const n = norm(e);
    const sys = SYSFILES.exec(n.decoded) ?? SYSFILES.exec(n.raw);
    const trav = TRAVERSAL.exec(n.decoded) ?? TRAVERSAL.exec(n.raw);
    if (!sys && !trav) return null;
    const m = (sys ?? trav) as RegExpExecArray;
    const name = sys ? 'SYSTEM FILE' : 'PATH TRAVERSAL';
    const extra = isDoubleEncoded(n.layers) ? ' (double encoded)' : '';
    return {
      id: `${e.id}:R2B_TRAVERSAL`,
      entryId: e.id,
      ip: e.ip,
      ts: e.ts,
      type: 'TRAVERSAL',
      ruleId: 'R2B_TRAVERSAL',
      severity: sys ? 3 : 2,
      evidence: `${name}: ${m[0].slice(0, 120)}${extra}`,
    };
  },
};
