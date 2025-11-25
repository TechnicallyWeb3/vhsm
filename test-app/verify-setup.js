#!/usr/bin/env node

/**
 * Verification script to check if test app is properly set up
 */

import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const checks = [
  {
    name: '.env file exists',
    check: () => existsSync(join(__dirname, '.env')),
    fix: 'Run: node create-env.js'
  },
  {
    name: '.env.keys file exists',
    check: () => existsSync(join(__dirname, '.env.keys')),
    fix: 'Run: dotenvx encrypt'
  },
  {
    name: '.env.keys.encrypted file exists',
    check: () => existsSync(join(__dirname, '.env.keys.encrypted')),
    fix: 'Run from project root: node dist/cli.js encrypt test-app/.env.keys -o test-app/.env.keys.encrypted'
  },
  {
    name: 'node_modules exists',
    check: () => existsSync(join(__dirname, 'node_modules')),
    fix: 'Run: npm install'
  },
  {
    name: 'dotenvx is installed',
    check: () => {
      try {
        const pkg = JSON.parse(readFileSync(join(__dirname, 'node_modules', '@dotenvx', 'dotenvx', 'package.json'), 'utf-8'));
        return true;
      } catch {
        return false;
      }
    },
    fix: 'Run: npm install'
  }
];

console.log('🔍 Verifying test app setup...\n');

let allPassed = true;

for (const { name, check, fix } of checks) {
  const passed = check();
  if (passed) {
    console.log(`✅ ${name}`);
  } else {
    console.log(`❌ ${name}`);
    console.log(`   Fix: ${fix}`);
    allPassed = false;
  }
}

console.log('');

if (allPassed) {
  console.log('✅ All checks passed! Test app is ready to use.');
  console.log('\nRun from project root:');
  console.log('  node dist/cli.js run -k test-app/.env.keys.encrypted -- node test-app/server.js');
  process.exit(0);
} else {
  console.log('❌ Some checks failed. Please fix the issues above.');
  process.exit(1);
}

