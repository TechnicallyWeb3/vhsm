#!/usr/bin/env node

/**
 * Test script for FIDO2 provider
 * 
 * This script tests:
 * 1. Encrypting a test string with FIDO2/Yubikey
 * 2. Decrypting it back
 * 3. Verifying the result matches the original
 * 
 * Requirements:
 * - A FIDO2-compatible device (Yubikey, etc.)
 * - The device must be plugged in
 * - A web browser for WebAuthn authentication
 */

import { FIDO2Provider, isFIDO2Available } from './dist/index.js';

async function testFIDO2() {
  console.log('=== FIDO2/Yubikey Provider Test ===\n');
  
  // Check availability
  console.log(`FIDO2 Available: ${isFIDO2Available()}\n`);
  
  if (!isFIDO2Available()) {
    console.log('❌ FIDO2 provider is not available');
    process.exit(1);
  }
  
  try {
    // Create provider
    console.log('Creating FIDO2 provider...');
    const provider = new FIDO2Provider();
    console.log(`✅ Provider created: ${provider.name}`);
    console.log(`   Requires interaction: ${provider.requiresInteraction}\n`);
    
    // Test string
    const testString = 'dotenvx_private_key_1234567890abcdef';
    console.log(`Original string: ${testString}\n`);
    
    // Encrypt
    console.log('Encrypting with FIDO2...');
    console.log('A browser window will open. Please follow the instructions.\n');
    const encrypted = await provider.encrypt(testString);
    console.log(`✅ Encrypted: ${encrypted.substring(0, 100)}...\n`);
    
    // Wait a moment
    console.log('Waiting 2 seconds before decryption...\n');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Decrypt
    console.log('Decrypting with FIDO2...');
    console.log('A browser window will open. Please touch your Yubikey when prompted.\n');
    const decrypted = await provider.decrypt(encrypted);
    console.log(`✅ Decrypted: ${decrypted}\n`);
    
    // Verify
    if (decrypted === testString) {
      console.log('✅ Success! Decrypted string matches original');
      console.log('\n=== Test Complete ===');
      process.exit(0);
    } else {
      console.log('❌ Error: Decrypted string does not match original');
      console.log(`   Expected: ${testString}`);
      console.log(`   Got:      ${decrypted}`);
      process.exit(1);
    }
  } catch (error) {
    console.error('❌ Error:', error.message);
    if (error.stack) {
      console.error('\nStack trace:');
      console.error(error.stack);
    }
    process.exit(1);
  }
}

testFIDO2();

