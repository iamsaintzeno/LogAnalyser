import type { LogEntry } from '../../contracts';

export const SCANNER_USER_AGENT_TOKENS: readonly string[] = Object.freeze([
  'sqlmap',
  'nikto',
  'nmap',
  'masscan',
  'zgrab',
  'gobuster',
  'ffuf',
  'dirbuster',
  'wpscan',
  'nuclei',
]);

export function findScannerToken(userAgent: string): string | null {
  const normalized = userAgent.toLowerCase();
  return SCANNER_USER_AGENT_TOKENS.find((token) => normalized.includes(token)) ?? null;
}

export function matchesScannerUserAgent(entry: LogEntry): boolean {
  return findScannerToken(entry.ua) !== null;
}
