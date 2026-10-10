import type { LogEntry } from '../../contracts';

const SQL_COMMENT_MARKERS: readonly string[] = Object.freeze(['--', '/*', '*/']);

function isWordCharacter(character: string | undefined): boolean {
  if (character === undefined) return false;
  const code = character.charCodeAt(0);
  return (code >= 48 && code <= 57) || (code >= 97 && code <= 122) || code === 95;
}

function containsPhraseAtWordBoundary(value: string, phrase: string): boolean {
  let start = value.indexOf(phrase);
  while (start !== -1) {
    const end = start + phrase.length;
    if (!isWordCharacter(value[start - 1]) && !isWordCharacter(value[end])) return true;
    start = value.indexOf(phrase, start + 1);
  }
  return false;
}

export function matchesSqlInjection(entry: LogEntry): boolean {
  const target = `${entry.path}?${entry.query}`.toLowerCase();
  if (containsPhraseAtWordBoundary(target, 'union select') || containsPhraseAtWordBoundary(target, 'or 1=1')) return true;
  return SQL_COMMENT_MARKERS.some((marker) => target.includes(marker));
}
