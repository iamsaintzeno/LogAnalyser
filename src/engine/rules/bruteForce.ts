import type { LogEntry, ThreatEvent, WindowRule, RuleConfig } from '../types';
import { BRUTE_FORCE } from '../constants';

const RULE_ID = 'R1_BRUTE_FORCE';
const AUTH_PATH = /^\/(?:wp-login\.php|xmlrpc\.php|wp-admin\/admin-ajax\.php|administrator\/index\.php|user\/login|login|admin\/login|users\/sign_in)(?:\/|$)/i;
const FORM_LOGIN = /^\/(?:login|admin\/login|users\/sign_in)/i;
const XMLRPC_STATUS = new Set([200, 401, 403, 405]);
const TAKEOVER_WINDOW_MS = 120000;

export function isAuthFailure(e: LogEntry): boolean {
  if (!AUTH_PATH.test(e.path)) return false;
  if (e.status === 401 || e.status === 403) return true;
  if (e.method !== 'POST') return false;
  const p = e.path.toLowerCase();
  // WordPress returns 200 + login form on a FAILED login (302 = success)
  if (p.startsWith('/wp-login.php') && e.status === 200) return true;
  if (p.startsWith('/xmlrpc.php') && XMLRPC_STATUS.has(e.status)) return true;
  return e.status === 200 && FORM_LOGIN.test(e.path);
}

function isLoginSuccess(e: LogEntry): boolean {
  return e.method === 'POST' && e.path.toLowerCase().startsWith('/wp-login.php') && e.status === 302;
}

function addTo(map: Map<string, LogEntry[]>, e: LogEntry): void {
  const list = map.get(e.ip);
  if (list) list.push(e);
  else map.set(e.ip, [e]);
}

// O(n log n): group per IP, sort by time, two-pointer sliding window.
export const bruteForceRule: WindowRule = {
  id: RULE_ID,
  type: 'BRUTE_FORCE',
  evaluateAll(entries: LogEntry[], cfg: RuleConfig): ThreatEvent[] {
    if (!cfg.enabled) return [];
    const threshold = Math.max(1, cfg.threshold ?? BRUTE_FORCE.THRESHOLD);
    const windowSec = cfg.windowSec ?? BRUTE_FORCE.WINDOW_SEC;
    const winMs = Math.max(0, windowSec * 1000);

    const failures = new Map<string, LogEntry[]>();
    const successes = new Map<string, LogEntry[]>();
    for (const e of entries) {
      if (isAuthFailure(e)) addTo(failures, e);
      else if (isLoginSuccess(e)) addTo(successes, e);
    }

    const events: ThreatEvent[] = [];
    for (const [ip, list] of failures) {
      list.sort((a, b) => a.ts - b.ts);
      const n = list.length;
      const diffMark = new Int32Array(n + 1);
      const diffSev = new Int32Array(n + 1);
      let peak = 0;
      let i = 0;
      for (let j = 0; j < n; j++) {
        while (list[j].ts - list[i].ts > winMs) i++;
        const count = j - i + 1;
        if (count >= threshold) {
          diffMark[i]++;
          diffMark[j + 1]--;
          if (count >= 3 * threshold) {
            diffSev[i]++;
            diffSev[j + 1]--;
          }
          if (count > peak) peak = count;
        }
      }
      if (peak === 0) continue;

      let mark = 0;
      let sev = 0;
      const markedTs: number[] = [];
      for (let k = 0; k < n; k++) {
        mark += diffMark[k];
        sev += diffSev[k];
        if (mark > 0) {
          const e = list[k];
          markedTs.push(e.ts);
          events.push({
            id: `${e.id}:${RULE_ID}`,
            entryId: e.id,
            ip,
            ts: e.ts,
            type: 'BRUTE_FORCE',
            ruleId: RULE_ID,
            severity: sev > 0 ? 3 : 2,
            evidence: `${peak} failed auth requests in ${windowSec}s`,
          });
        }
      }

      // ONE extra event: successful login within 120s after a marked failure
      const succ = successes.get(ip);
      if (succ) {
        succ.sort((a, b) => a.ts - b.ts);
        let p = -1;
        for (const s of succ) {
          while (p + 1 < markedTs.length && markedTs[p + 1] <= s.ts) p++;
          if (p >= 0 && s.ts - markedTs[p] <= TAKEOVER_WINDOW_MS) {
            events.push({
              id: `${s.id}:${RULE_ID}`,
              entryId: s.id,
              ip,
              ts: s.ts,
              type: 'BRUTE_FORCE',
              ruleId: RULE_ID,
              severity: 3,
              evidence: 'Possible account takeover: successful login after brute force',
            });
            break;
          }
        }
      }
    }
    return events;
  },
};
