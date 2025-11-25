#!/usr/bin/env node

/**
 * Demo script showing vhsm workflow
 */

console.log('📦 vhsm Demo Application\n');
console.log('This demonstrates the vhsm + dotenvx workflow:\n');
console.log('1. Environment variables are loaded via dotenvx');
console.log('2. The dotenvx private key was decrypted by vhsm');
console.log('3. All secrets are secure and never touch disk in plaintext\n');
console.log('─'.repeat(60));
console.log('Current Environment:\n');

const envVars = Object.keys(process.env)
  .filter(key => key.startsWith('DATABASE_') || key.startsWith('API_') || key.startsWith('SECRET_') || key === 'NODE_ENV' || key === 'PORT')
  .sort();

envVars.forEach(key => {
  const value = process.env[key];
  const displayValue = key.includes('KEY') || key.includes('TOKEN') || key.includes('SECRET')
    ? '***' + value.slice(-4)
    : value;
  console.log(`  ${key}: ${displayValue}`);
});

console.log('\n─'.repeat(60));
console.log('✅ Demo complete! Environment variables loaded successfully.\n');

