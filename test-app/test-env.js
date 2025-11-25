#!/usr/bin/env node

/**
 * Test script to verify environment variables are loaded
 */

console.log('🧪 Testing Environment Variables\n');
console.log('─'.repeat(60));

const requiredVars = [
  'DATABASE_URL',
  'API_KEY',
  'SECRET_TOKEN',
  'NODE_ENV',
  'PORT'
];

let allPresent = true;

requiredVars.forEach(varName => {
  const value = process.env[varName];
  if (value) {
    // Mask sensitive values
    const displayValue = varName.includes('KEY') || varName.includes('TOKEN') || varName.includes('SECRET')
      ? '***' + value.slice(-4)
      : value;
    console.log(`✅ ${varName}: ${displayValue}`);
  } else {
    console.log(`❌ ${varName}: (not set)`);
    allPresent = false;
  }
});

console.log('─'.repeat(60));

if (allPresent) {
  console.log('\n✅ All environment variables are loaded correctly!');
  process.exit(0);
} else {
  console.log('\n❌ Some environment variables are missing!');
  process.exit(1);
}

