#!/usr/bin/env node

/**
 * Simple test server that uses environment variables
 * This demonstrates vhsm + dotenvx integration
 */

const port = process.env.PORT || 3000;
const nodeEnv = process.env.NODE_ENV || 'development';

console.log('🚀 Starting test server...\n');
console.log('Environment Variables Loaded:');
console.log('─'.repeat(50));
console.log(`NODE_ENV: ${nodeEnv}`);
console.log(`PORT: ${port}`);
console.log(`DATABASE_URL: ${process.env.DATABASE_URL || '(not set)'}`);
console.log(`API_KEY: ${process.env.API_KEY ? '***' + process.env.API_KEY.slice(-4) : '(not set)'}`);
console.log(`SECRET_TOKEN: ${process.env.SECRET_TOKEN ? '***' + process.env.SECRET_TOKEN.slice(-4) : '(not set)'}`);
console.log('─'.repeat(50));
console.log(`\n✅ Server would start on port ${port}`);
console.log('✅ Environment variables are loaded and secure!\n');

// Simulate server running
console.log('Press Ctrl+C to stop...\n');

// Keep process alive for demo
setTimeout(() => {
  console.log('⏱️  Demo timeout reached. Exiting...');
  process.exit(0);
}, 5000);

