#!/usr/bin/env node

/**
 * Test script for TPM2 provider
 * 
 * This script tests:
 * 1. Checking if TPM2 tools are available
 * 2. Encrypting a test string with TPM2
 * 3. Decrypting it back
 * 4. Testing with auth password
 * 5. Verifying the result matches the original
 */

import { TPM2Provider, isTPM2Available } from './dist/index.js';
import { platform } from 'os';

async function testTPM2() {
  console.log('=== TPM2 Provider Test ===\n');
  
  // Check if TPM2 tools are available
  console.log(`Platform: ${platform()}`);
  console.log(`TPM2 Tools Available: ${isTPM2Available()}\n`);
  
  if (!isTPM2Available()) {
    console.log('❌ TPM2 tools not found. Install tpm2-tools:');
    console.log('   Linux:   sudo apt install tpm2-tools');
    console.log('   macOS:   brew install tpm2-tools');
    console.log('   Windows: Use Docker with Linux container (see test-app/DOCKER.md)\n');
    process.exit(1);
  }
  
  try {
    // Create provider
    console.log('Creating TPM2 provider...');
    const provider = new TPM2Provider();
    console.log(`✅ Provider created: ${provider.name}`);
    console.log(`   Requires interaction: ${provider.requiresInteraction}\n`);
    
    // Test string
    const testString = 'dotenvx_private_key_test_1234567890';
    console.log(`Original string: ${testString}\n`);
    
    // Test 1: Encrypt/Decrypt without auth
    console.log('--- Test 1: Without Authorization Password ---');
    console.log('Encrypting with TPM2 (no auth)...');
    const encrypted1 = provider.encrypt(testString);
    console.log(`✅ Encrypted (${encrypted1.length} chars): ${encrypted1.substring(0, 50)}...\n`);
    
    console.log('Decrypting with TPM2 (no auth)...');
    const decrypted1 = await provider.decrypt(encrypted1);
    console.log(`✅ Decrypted: ${decrypted1}\n`);
    
    if (decrypted1 === testString) {
      console.log('✅ Test 1 PASSED: Decrypted string matches original\n');
    } else {
      console.log('❌ Test 1 FAILED: Decrypted string does not match');
      console.log(`   Expected: ${testString}`);
      console.log(`   Got:      ${decrypted1}\n`);
      process.exit(1);
    }
    
    // Test 2: Encrypt/Decrypt with auth password
    console.log('--- Test 2: With Authorization Password ---');
    const authPassword = 'TestPassword123';
    console.log(`Using auth password: ${authPassword}`);
    
    console.log('Encrypting with TPM2 (with auth)...');
    const encrypted2 = provider.encrypt(testString, authPassword);
    console.log(`✅ Encrypted (${encrypted2.length} chars): ${encrypted2.substring(0, 50)}...\n`);
    
    console.log('Decrypting with TPM2 (with auth)...');
    const decrypted2 = await provider.decrypt(encrypted2, authPassword);
    console.log(`✅ Decrypted: ${decrypted2}\n`);
    
    if (decrypted2 === testString) {
      console.log('✅ Test 2 PASSED: Decrypted string matches original\n');
    } else {
      console.log('❌ Test 2 FAILED: Decrypted string does not match');
      console.log(`   Expected: ${testString}`);
      console.log(`   Got:      ${decrypted2}\n`);
      process.exit(1);
    }
    
    // Test 3: Try to decrypt with wrong password (should fail)
    console.log('--- Test 3: Wrong Password (Should Fail) ---');
    try {
      console.log('Attempting to decrypt with wrong password...');
      await provider.decrypt(encrypted2, 'WrongPassword');
      console.log('❌ Test 3 FAILED: Should have thrown an error\n');
      process.exit(1);
    } catch (error) {
      console.log(`✅ Test 3 PASSED: Correctly rejected wrong password`);
      console.log(`   Error: ${error.message}\n`);
    }
    
    // Test 4: Try to decrypt auth-protected data without password (should fail)
    console.log('--- Test 4: Missing Required Password (Should Fail) ---');
    try {
      console.log('Attempting to decrypt auth-protected data without password...');
      await provider.decrypt(encrypted2);
      console.log('❌ Test 4 FAILED: Should have thrown an error\n');
      process.exit(1);
    } catch (error) {
      console.log(`✅ Test 4 PASSED: Correctly required password`);
      console.log(`   Error: ${error.message}\n`);
    }
    
    console.log('=================================');
    console.log('✅ All Tests PASSED!');
    console.log('=================================');
    console.log('\nTPM2 provider is working correctly!');
    console.log('Your sealed keys are protected by hardware.\n');
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    if (error.stack) {
      console.error('\nStack trace:');
      console.error(error.stack);
    }
    process.exit(1);
  }
}

testTPM2();

