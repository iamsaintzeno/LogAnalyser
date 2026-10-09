import type { LogEntry } from '../../contracts';
import { decodeOnceSafely } from '../decode';

export function matchesTraversal(entry: LogEntry): boolean {
  const path = decodeOnceSafely(entry.path);
  const query = decodeOnceSafely(entry.query);
  return path.includes('../') || query.includes('../');
}
