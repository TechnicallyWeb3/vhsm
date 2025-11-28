#!/usr/bin/env node

/**
 * Test allowExec security gate
 */

import { exec } from '../dist/index.js';

async function testAllowExec() {
  console.log('Testing allowExec security gate...\n');
  
  // Test 1: Should fail without allowExec
  console.log('Test 1: Exec without allowExec (should fail)');
  try {
    await exec(
      () => 'test',
      {},
      {}
    );
    console.log('❌ FAILED: Should have thrown an error');
  } catch (error) {
    console.log('✅ PASSED: Correctly blocked execution');
    console.log(`   Error: ${error.message}\n`);
  }
  
  // Test 2: Should work with env var
  console.log('Test 2: Exec with VHSM_ALLOW_EXEC=true');
  process.env.VHSM_ALLOW_EXEC = 'true';
  try {
    const result = await exec(
      ({ message }) => message,
      { message: 'success' },
      {}
    );
    console.log('✅ PASSED: Execution allowed');
    console.log(`   Result: ${result}\n`);
  } catch (error) {
    console.log('❌ FAILED: Should have worked');
    console.log(`   Error: ${error.message}\n`);
  }
  
  // Test 3: Should work with option override
  delete process.env.VHSM_ALLOW_EXEC;
  console.log('Test 3: Exec with allowExec option override');
  try {
    const result = await exec(
      ({ message }) => message,
      { message: 'success' },
      { allowExec: true }
    );
    console.log('✅ PASSED: Execution allowed via option');
    console.log(`   Result: ${result}\n`);
  } catch (error) {
    console.log('❌ FAILED: Should have worked');
    console.log(`   Error: ${error.message}\n`);
  }
  
  console.log('All tests completed!');
}

testAllowExec().catch(console.error);

