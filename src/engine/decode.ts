// Safe URI normalizer. Attackers hide payloads with %27, %2527 (double encoding), SQL comments, etc.
// Decode first, then the detection rules match on the clean text.

const MAX_LAYERS = 3;
const MAX_OUTPUT = 4096;

// Tolerant decoder: only decodes valid %HH pairs and leaves broken ones alone. Linear-time regex.
function tolerantDecode(s: string): string {
  return s.replace(/%([0-9a-fA-F]{2})/g, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}

function decodeOnce(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return tolerantDecode(s);
  }
}

export function normalizeTarget(path: string, query: string): { decoded: string; raw: string; layers: number } {
  const raw = path + (query ? '?' + query : '');

  // '+' means space, but only in the query part
  let s = path + (query ? '?' + query.replace(/\+/g, ' ') : '');

  let layers = 0;
  for (let i = 0; i < MAX_LAYERS; i++) {
    const next = decodeOnce(s);
    if (next === s) break;
    s = next;
    layers++;
  }

  s = s
    .replace(/\0/g, '') // remove NUL bytes
    .replace(/\\/g, '/') // backslash -> slash
    .replace(/\/\*[\s\S]{0,200}?\*\//g, ' ') // SQL inline comments -> one space
    .replace(/\s+/g, ' ') // collapse whitespace
    .toLowerCase();

  if (s.length > MAX_OUTPUT) s = s.slice(0, MAX_OUTPUT);

  return { decoded: s, raw, layers };
}

// Double encoding is itself suspicious.
export function isDoubleEncoded(layers: number): boolean {
  return layers >= 2;
}
