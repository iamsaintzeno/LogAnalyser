import type { LogEntry } from '../../contracts';

export const SENSITIVE_PATHS: readonly string[] = Object.freeze([
  '/.env',
  '/.git/config',
  '/wp-config.php',
  '/config.php',
  '/etc/passwd',
  '/phpinfo.php',
  '/server-status',
  '/adminer.php',
  '/backup.zip',
  '/config.json',
]);

const SENSITIVE_PATH_SET: ReadonlySet<string> = new Set(SENSITIVE_PATHS);

export function matchesSensitivePath(entry: LogEntry): boolean {
  return SENSITIVE_PATH_SET.has(entry.path.toLowerCase());
}
