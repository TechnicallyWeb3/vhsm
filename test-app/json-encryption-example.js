/**
 * vHSM JSON Encryption Example
 * 
 * This example demonstrates:
 * 1. Encrypting JSON files with vHSM
 * 2. Loading encrypted JSON files programmatically
 * 3. Using JSON values in exec() with dot notation
 * 4. Decrypting JSON files via CLI
 */

import { encryptJsonFile, loadFile, getJsonValue, exec } from 'vhsm';
import { writeFileSync, existsSync, unlinkSync } from 'node:fs';

async function main() {
  console.log('🔐 vHSM JSON Encryption Example\n');
  
  // Step 1: Create a sample JSON file
  console.log('Step 1: Creating sample JSON file...');
  const sampleData = {
    user: {
      name: 'John Doe',
      age: 42,
      email: 'john@example.com'
    },
    message: 'Hello World',
    apiKeys: {
      primary: 'sk_live_abc123',
      secondary: 'sk_live_xyz789'
    },
    database: {
      host: 'localhost',
      port: 5432,
      credentials: {
        username: 'admin',
        password: 'super_secret_password'
      }
    }
  };
  
  const jsonFilePath = './test-data.json';
  writeFileSync(jsonFilePath, JSON.stringify(sampleData, null, 2));
  console.log(`✅ Created ${jsonFilePath}\n`);
  
  try {
    // Step 2: Encrypt the JSON file
    console.log('Step 2: Encrypting JSON file...');
    console.log('Note: You can also use the CLI: vhsm encrypt test-data.json\n');
    
    await encryptJsonFile(jsonFilePath, {
      provider: 'password',
      password: 'test-password-123',
      deleteOriginal: false, // Keep original for comparison
    });
    
    console.log('\n✅ JSON file encrypted!\n');
    
    // Step 3: Load the entire encrypted JSON file
    console.log('Step 3: Loading entire encrypted JSON file...');
    const decryptedData = await loadFile('./test-data.encrypted.json', {
      password: 'test-password-123',
    });
    
    console.log('Decrypted data:');
    console.log(JSON.stringify(decryptedData, null, 2));
    console.log();
    
    // Step 4: Get specific values using dot notation
    console.log('Step 4: Getting specific values with dot notation...');
    
    const userName = await getJsonValue('./test-data.encrypted.json', 'user.name', {
      password: 'test-password-123',
    });
    console.log(`user.name = ${userName}`);
    
    const userAge = await getJsonValue('./test-data.encrypted.json', 'user.age', {
      password: 'test-password-123',
    });
    console.log(`user.age = ${userAge}`);
    
    const dbPassword = await getJsonValue('./test-data.encrypted.json', 'database.credentials.password', {
      password: 'test-password-123',
    });
    console.log(`database.credentials.password = ${dbPassword}`);
    console.log();
    
    // Step 5: Use JSON values in exec() with @vhsm syntax
    console.log('Step 5: Using JSON values in exec() with @vhsm syntax...');
    console.log('Note: Make sure VHSM_ALLOW_EXEC=true is set\n');
    
    // Check if exec is allowed
    if (process.env.VHSM_ALLOW_EXEC !== 'true') {
      console.log('⚠️  Skipping exec() example - VHSM_ALLOW_EXEC is not set to true');
      console.log('   To run this example, set: export VHSM_ALLOW_EXEC=true\n');
    } else {
      // Example 1: Load entire JSON file
      const result1 = await exec(
        async ({ data }) => {
          console.log('Received entire JSON data:');
          console.log(JSON.stringify(data, null, 2));
          return data.message;
        },
        {
          data: '@vhsm test-data.encrypted.json'
        },
        {
          password: 'test-password-123',
        }
      );
      console.log(`Function returned: ${result1}\n`);
      
      // Example 2: Get specific value using dot notation
      const result2 = await exec(
        async ({ userName, userEmail, apiKey }) => {
          console.log(`Processing user: ${userName} (${userEmail})`);
          console.log(`Using API key: ${apiKey}`);
          return `Hello, ${userName}!`;
        },
        {
          userName: '@vhsm test-data.encrypted.json user.name',
          userEmail: '@vhsm test-data.encrypted.json user.email',
          apiKey: '@vhsm test-data.encrypted.json apiKeys.primary'
        },
        {
          password: 'test-password-123',
        }
      );
      console.log(`Function returned: ${result2}\n`);
      
      // Example 3: Mix JSON values with regular env variables
      console.log('Example 3: Mixing JSON values with .env variables...');
      console.log('(This would work if you have encrypted .env files)\n');
    }
    
    // Step 6: CLI usage examples
    console.log('Step 6: CLI Usage Examples\n');
    console.log('Encrypt a JSON file:');
    console.log('  vhsm encrypt test-data.json\n');
    console.log('Decrypt a JSON file:');
    console.log('  vhsm decrypt test-data.encrypted.json\n');
    console.log('Encrypt with specific provider:');
    console.log('  vhsm encrypt test-data.json -p fido2\n');
    console.log('Keep original file after encryption:');
    console.log('  vhsm encrypt test-data.json --no-delete\n');
    
    console.log('\n✅ Example completed successfully!');
    
  } catch (error) {
    console.error('\n❌ Error:', error instanceof Error ? error.message : error);
    process.exit(1);
  } finally {
    // Cleanup
    console.log('\nCleaning up example files...');
    const filesToClean = [
      './test-data.json',
      './test-data.encrypted.json',
      './.env.test-data.json',
    ];
    
    for (const file of filesToClean) {
      if (existsSync(file)) {
        unlinkSync(file);
        console.log(`Deleted: ${file}`);
      }
    }
  }
}

// Run the example
main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

