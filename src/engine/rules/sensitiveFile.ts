import type { LogEntry, ThreatEvent, Rule } from '../types';
import { normalizeTarget } from '../decode';

const RULE_ID = 'R4_SENSITIVE_PROBE';

const SENSITIVE_PREFIX = /^\/(?:\.env(?:\.[\w.-]{1,20})?|\.git(?:\/|$)|\.svn(?:\/|$)|\.hg(?:\/|$)|\.htpasswd|\.htaccess|\.ds_store|\.aws\/|\.ssh\/|wp-config\.php|wp-config-sample\.php|wp-content\/debug\.log|phpinfo\.php|info\.php|server-status|server-info|phpmyadmin(?:\/|$)|pma(?:\/|$)|adminer(?:\.php)?|id_rsa|config\.(?:php|json|yml|yaml|ini)|settings\.py|web\.config|docker-compose\.ya?ml|\.dockerenv|composer\.(?:json|lock)|package\.json)/;
const SENSITIVE_SUFFIX = /(?:\.(?:bak|old|orig|save|swp|sql|sqlite|db|dump|tar|tar\.gz|tgz|zip|rar|7z|log))$|~$/;
const SENSITIVE_NAMES = /(?:^|\/)(?:backup|backups|db|database|dump|site|www|public_html|wordpress)\.(?:sql|zip|tar\.gz|tgz|rar)$/;

// Normal download folders: a .zip here is not an attack.
const SAFE_DIR = /^\/(?:wp-content\/uploads\/|static\/|assets\/)/;

export const sensitiveFileRule: Rule = {
  id: RULE_ID,
  type: 'SENSITIVE_PROBE',
  evaluate(e: LogEntry): ThreatEvent | null {
    // Decoded PATH only (decode handles %2e%65nv and lower-cases). Ignore the query.
    const path = normalizeTarget(e.path, '').decoded.split('?')[0];

    const hit =
      SENSITIVE_PREFIX.test(path) ||
      SENSITIVE_NAMES.test(path) ||
      (SENSITIVE_SUFFIX.test(path) && !SAFE_DIR.test(path));
    if (!hit) return null;

    // 200/206 = the file was actually served. 404/403 etc. = attempted probe.
    // (Even /.git/HEAD, /.git/config and /.env get severity >= 2 because the lowest value here is 2.)
    const exposed = e.status === 200 || e.status === 206;
    const shown = path.length > 100 ? path.slice(0, 100) + '...' : path;
    return {
      id: `${e.id}:${RULE_ID}`,
      entryId: e.id,
      ip: e.ip,
      ts: e.ts,
      type: 'SENSITIVE_PROBE',
      ruleId: RULE_ID,
      severity: exposed ? 3 : 2,
      evidence: exposed ? `EXPOSED: ${shown}` : `Sensitive file probe: ${shown}`,
    };
  },
};
