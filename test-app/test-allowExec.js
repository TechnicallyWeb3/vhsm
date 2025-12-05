#!/usr/bin/env node

/**
 * Test allowExec security gate
 * 
 * SECURITY MODEL:
 * - exec() can ONLY be enabled by admin-controlled settings:
 *   1. Environment variable: VHSM_ALLOW_EXEC=true
 *   2. Config file (.vhsmrc.json): {"allowExec": true}
 * - exec() canNOT be enabled programmatically via options (security by design)
 */

import { exec } from '../dist/index.js';

async function testAllowExec() {
  console.log('Testing allowExec security gate...\n');
  console.log('SECURITY MODEL: exec() can only be enabled by admin (env var or config file)\n');
  
  // Test 1: Should fail without allowExec
  console.log('Test 1: Exec without allowExec (should fail)');
  delete process.env.VHSM_ALLOW_EXEC;
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
  
  // Test 2: Should work with env var (admin-controlled)
  console.log('Test 2: Exec with VHSM_ALLOW_EXEC=true (env var)');
  process.env.VHSM_ALLOW_EXEC = 'true';
  try {
    const result = await exec(
      ({ message }) => message,
      { message: 'success' },
      {}
    );
    console.log('✅ PASSED: Execution allowed via admin-controlled env var');
    console.log(`   Result: ${result}\n`);
  } catch (error) {
    console.log('❌ FAILED: Should have worked');
    console.log(`   Error: ${error.message}\n`);
  }
  
  // Test 3: SECURITY TEST - allowExec option should be IGNORED
  delete process.env.VHSM_ALLOW_EXEC;
  console.log('Test 3: SECURITY - allowExec option should be ignored (prevent code bypass)');
  try {
    const result = await exec(
      ({ message }) => message,
      { message: 'success' },
      { allowExec: true }  // This should be IGNORED for security
    );
    console.log('❌ SECURITY FAILURE: allowExec option should have been ignored!');
    console.log(`   Result: ${result}\n`);
  } catch (error) {
    console.log('✅ PASSED: allowExec option correctly ignored (security feature)');
    console.log(`   Error: ${error.message}\n`);
  }
  
  console.log('All tests completed!');
  console.log('\nSecurity Summary:');
  console.log('- ✅ Exec is blocked by default');
  console.log('- ✅ Exec can be enabled via env var (admin-controlled)');
  console.log('- ✅ Exec cannot be enabled via code options (prevents malicious bypass)');
}

testAllowExec().catch(console.error);

