#!/usr/bin/env node

/**
 * Test script for DPAPI provider
 * 
 * This script tests:
 * 1. Encrypting a test string with DPAPI
 * 2. Decrypting it back
 * 3. Verifying the result matches the original
 */

import { DPAPIProvider, isDPAPIAvailable } from './dist/index.js';
import { platform } from 'os';

async function testDPAPI() {
  console.log('=== DPAPI Provider Test ===\n');
  
  // Check platform
  console.log(`Platform: ${platform()}`);
  console.log(`DPAPI Available: ${isDPAPIAvailable()}\n`);
  
  if (!isDPAPIAvailable()) {
    console.log('❌ DPAPI is only available on Windows');
    process.exit(1);
  }
  
  try {
    // Create provider
    console.log('Creating DPAPI provider...');
    const provider = new DPAPIProvider();
    console.log(`✅ Provider created: ${provider.name}`);
    console.log(`   Requires interaction: ${provider.requiresInteraction}\n`);
    
    // Test string
    const testString = 'dotenvx_private_key_1234567890abcdef';
    console.log(`Original string: ${testString}\n`);
    
    // Encrypt
    console.log('Encrypting with DPAPI...');
    const encrypted = provider.encrypt(testString);
    console.log(`✅ Encrypted (${encrypted.length} chars): ${encrypted.substring(0, 50)}...\n`);
    
    // Decrypt
    console.log('Decrypting with DPAPI...');
    const decrypted = await provider.decrypt(encrypted);
    console.log(`✅ Decrypted: ${decrypted}\n`);
    
    // Verify
    if (decrypted === testString) {
      console.log('✅ Success! Decrypted string matches original');
      process.exit(0);
    } else {
      console.log('❌ Error: Decrypted string does not match original');
      console.log(`   Expected: ${testString}`);
      console.log(`   Got:      ${decrypted}`);
      process.exit(1);
    }
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

testDPAPI();
