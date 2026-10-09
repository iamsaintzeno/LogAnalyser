/** Decode percent escapes once; invalid escapes are kept as text instead of throwing. */
export function decodeOnceSafely(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    let decoded = '';
    for (let index = 0; index < value.length; index += 1) {
      if (value[index] === '%' && index + 2 < value.length) {
        const high = hexValue(value.charCodeAt(index + 1));
        const low = hexValue(value.charCodeAt(index + 2));
        if (high >= 0 && low >= 0) {
          const code = high * 16 + low;
          if (code < 128) {
            decoded += String.fromCharCode(code);
          } else {
            decoded += value.slice(index, index + 3);
          }
          index += 2;
          continue;
        }
      }
      decoded += value[index];
    }
    return decoded;
  }
}

function hexValue(code: number): number {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 65 && code <= 70) return code - 55;
  if (code >= 97 && code <= 102) return code - 87;
  return -1;
}
