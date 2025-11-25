#!/usr/bin/env node

/**
 * Helper script to reset all env files to the unencrypted template.
 *
 * Copies .env.template into each env variant so you can re-encrypt from scratch.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const TEMPLATE_PATH = resolve('.env.template');
const TARGET_FILES = ['.env', '.env.local', '.env.production', '.env.secure'];

if (!existsSync(TEMPLATE_PATH)) {
  console.error('❌ Missing .env.template. Please create one before running this script.');
  process.exit(1);
}

const templateContent = readFileSync(TEMPLATE_PATH, 'utf-8');

for (const file of TARGET_FILES) {
  writeFileSync(resolve(file), templateContent);
  console.log(`✅ Reset ${file}`);
}

console.log('\nAll environment files have been reset to the unencrypted template.');
console.log('Next steps: run `dotenvx encrypt` followed by `vhsm encrypt ...` with your preferred provider.');

