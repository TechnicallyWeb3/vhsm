/**
 * Quick test for JSON encryption feature
 * 
 * Run with VHSM_DEBUG=true to see detailed logging:
 *   VHSM_DEBUG=true node test-json-encryption.js
 */

import { writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { encryptJsonFile, loadFile, getJsonValue } from './dist/index.js';

async function test() {
  console.log('🧪 Testing JSON Encryption Feature\n');
  
  if (process.env.VHSM_DEBUG === 'true') {
    console.log('📝 Debug mode enabled\n');
  }
  
  try {
    // Step 1: Create test JSON file
    console.log('1. Creating test JSON file...');
    const testData = {
      user: {
        name: 'Test User',
        age: 30,
      },
      message: 'Hello from vHSM!',
      nested: {
        deep: {
          value: 'Deep nested value'
        }
      }
    };
    
    writeFileSync('test.json', JSON.stringify(testData, null, 2));
    console.log('✅ Created test.json\n');
    
    // Step 2: Encrypt the JSON file
    console.log('2. Encrypting JSON file...');
    await encryptJsonFile('test.json', {
      provider: 'password',
      password: 'test-password-123',
      deleteOriginal: false,
    });
    console.log('✅ Encryption complete\n');
    
    // Step 3: Load entire file
    console.log('3. Loading entire encrypted JSON file...');
    const loadedData = await loadFile('test.encrypted.json', {
      password: 'test-password-123',
    });
    console.log('Loaded data:', JSON.stringify(loadedData, null, 2));
    console.log('✅ Load successful\n');
    
    // Step 4: Get specific values
    console.log('4. Getting specific values with dot notation...');
    
    const userName = await getJsonValue('test.encrypted.json', 'user.name', {
      password: 'test-password-123',
    });
    console.log(`user.name = "${userName}"`);
    
    const userAge = await getJsonValue('test.encrypted.json', 'user.age', {
      password: 'test-password-123',
    });
    console.log(`user.age = ${userAge}`);
    
    const deepValue = await getJsonValue('test.encrypted.json', 'nested.deep.value', {
      password: 'test-password-123',
    });
    console.log(`nested.deep.value = "${deepValue}"`);
    console.log('✅ Dot notation access successful\n');
    
    // Verify values
    if (userName !== 'Test User') throw new Error('userName mismatch');
    if (userAge !== 30) throw new Error('userAge mismatch');
    if (deepValue !== 'Deep nested value') throw new Error('deepValue mismatch');
    
    console.log('✅ All tests passed!\n');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
  } finally {
    // Cleanup
    console.log('Cleaning up test files...');
    const filesToClean = [
      'test.json',
      'test.encrypted.json',
      '.env.test.json',
    ];
    
    for (const file of filesToClean) {
      if (existsSync(file)) {
        unlinkSync(file);
        console.log(`Deleted: ${file}`);
      }
    }
    console.log('✅ Cleanup complete');
  }
}

test().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

