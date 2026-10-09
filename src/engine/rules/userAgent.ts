import type { LogEntry, ThreatEvent, Rule } from '../types';

const UA_STRONG = /(?:sqlmap|nikto|nmap(?:\s|\/|$)|nessus|openvas|acunetix|netsparker|w3af|dirbuster|dirb\b|gobuster|feroxbuster|ffuf|wfuzz|masscan|zgrab|wpscan|hydra|havij|arachni|nuclei|burp(?:suite)?|owasp.?zap|metasploit|sqlninja|jaeles|commix|whatweb|skipfish)/i;
const UA_WEAK = /(?:python-requests|python-urllib|go-http-client|libwww-perl|curl\/|wget\/|java\/\d|okhttp|scrapy|httpclient|node-fetch|axios\/)/i;
const UA_EMPTY = /^(?:-|\s*)$/;
const PROBE_PATH = /^\/(?:wp-login|xmlrpc|\.env|\.git|admin|phpmyadmin)/i;

// Lower-case names for the UI legend.
export const SCANNER_TOKENS: string[] = [
  'sqlmap', 'nikto', 'nmap', 'nessus', 'openvas', 'acunetix', 'netsparker', 'w3af',
  'dirbuster', 'dirb', 'gobuster', 'feroxbuster', 'ffuf', 'wfuzz', 'masscan', 'zgrab',
  'wpscan', 'hydra', 'havij', 'arachni', 'nuclei', 'burpsuite', 'owasp zap', 'metasploit',
  'sqlninja', 'jaeles', 'commix', 'whatweb', 'skipfish',
];

function tokenOf(matched: string): string {
  return matched.replace(/[\s/\d]+$/, '').toLowerCase();
}

function make(e: LogEntry, severity: 1 | 3, evidence: string): ThreatEvent {
  return {
    id: `${e.id}:R3_SCANNER_UA`,
    entryId: e.id,
    ip: e.ip,
    ts: e.ts,
    type: 'SCANNER_UA',
    ruleId: 'R3_SCANNER_UA',
    severity,
    evidence,
  };
}

export const userAgentRule: Rule = {
  id: 'R3_SCANNER_UA',
  type: 'SCANNER_UA',
  evaluate(e: LogEntry): ThreatEvent | null {
    const ua = e.ua;

    // Strong hacking-tool match: always an event.
    const strong = UA_STRONG.exec(ua);
    if (strong) return make(e, 3, `${tokenOf(strong[0])} user agent`);

    // Weak or empty UA counts ONLY when the request looks bad (4xx/5xx or a probing path),
    // so normal API clients getting 200 on /api/ are not flagged.
    const suspicious = e.status >= 400 || PROBE_PATH.test(e.path);
    if (!suspicious) return null;

    if (UA_EMPTY.test(ua)) return make(e, 1, 'Empty user agent');

    const weak = UA_WEAK.exec(ua);
    if (weak) return make(e, 1, `${tokenOf(weak[0])} user agent`);

    return null;
  },
};
