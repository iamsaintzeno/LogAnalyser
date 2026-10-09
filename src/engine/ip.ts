// Strict IPv4 check (4 octets, 0-255, no leading zeros) and a simple IPv6 check.
export function isValidIp(ip: string): boolean {
  if (ip.includes(':')) {
    const colons = ip.split(':').length - 1;
    return /^[0-9a-fA-F:.]+$/.test(ip) && colons >= 2;
  }
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}
