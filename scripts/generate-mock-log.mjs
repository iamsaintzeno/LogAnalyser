import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateMockLog } from '../src/lib/mockLogCore.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const seedArgument = process.argv[2];
const seed = seedArgument === undefined ? 20261009 : Number(seedArgument);
if (!Number.isFinite(seed)) throw new TypeError('seed must be a finite number');

const { text, truth } = generateMockLog(seed);
const publicDirectory = resolve(root, 'public');
await mkdir(publicDirectory, { recursive: true });
await Promise.all([
  writeFile(resolve(publicDirectory, 'sample-nginx-5000.log'), text, 'utf8'),
  writeFile(
    resolve(publicDirectory, 'mock-truth.json'),
    `${JSON.stringify({ seed, lineCount: truth.length, truth })}\n`,
    'utf8',
  ),
]);
console.log(`Generated ${truth.length} deterministic lines with seed ${seed}.`);
