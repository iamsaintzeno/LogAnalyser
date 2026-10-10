import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.resolve(process.argv[2] ?? path.join(root, 'frontend', 'dist'));
const resourcePattern = /(?:src|href)\s*=\s*["'](https?:\/\/[^"']+)["']|url\(\s*["']?(https?:\/\/[^"')]+)|@import\s+["'](https?:\/\/[^"']+)["']/gi;
const networkCallPattern = /\b(?:fetch|WebSocket|EventSource|sendBeacon)\s*\(\s*["'`](https?:\/\/[^"'`]+)/gi;
const allowlistedHosts = new Set(['www.w3.org', 'reactjs.org']);
const violations = [];

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(fullPath));
    else if (/\.(?:html|css|js|mjs)$/i.test(entry.name)) files.push(fullPath);
  }
  return files;
}

try {
  const files = await walk(dist);
  for (const file of files) {
    const content = await readFile(file, 'utf8');
    for (const pattern of [resourcePattern, networkCallPattern]) {
      for (const match of content.matchAll(pattern)) {
        const url = match[1] ?? match[2] ?? match[3];
        if (!url || allowlistedHosts.has(new URL(url).hostname)) continue;
        violations.push(`${path.relative(root, file)}: ${url}`);
      }
    }
  }
  if (violations.length) {
    console.error(`Offline check failed; external resource/network URLs found:\n${violations.join('\n')}`);
    process.exitCode = 1;
  } else {
    console.log(`Offline check passed: scanned ${files.length} built HTML/CSS/JS files.`);
  }
} catch (error) {
  console.error(`Offline check could not scan ${dist}:`, error);
  process.exitCode = 1;
}
