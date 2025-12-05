#!/usr/bin/env node

/**
 * Example demonstrating vhsm.exec() - Secure function execution with env variable injection
 * 
 * This example shows how to execute functions with automatic decryption and injection
 * of environment variables marked with the "@vhsm " prefix.
 * 
 * SECURITY: Before running, you must enable exec via environment variable:
 *   export VHSM_ALLOW_EXEC=true  (or set in .vhsmrc.json)
 * 
 * exec() cannot be enabled programmatically - this is a security feature to prevent
 * malicious code from bypassing admin restrictions.
 */

import { exec } from '../dist/index.js';

// Enable exec for this example (in production, set this via environment or config file)
process.env.VHSM_ALLOW_EXEC = 'true';

/**
 * Example signing function that uses an API key
 */
async function signMessage({ message, nonce, apiKey }) {
  // Simulate a signing operation
  console.log(`\n🔐 Signing message with API key...`);
  console.log(`   Message: ${message}`);
  console.log(`   Nonce: ${nonce}`);
  console.log(`   API Key: ${apiKey ? '***' + apiKey.slice(-4) : 'NOT PROVIDED'}`);
  
  // In a real scenario, you would use the API key here
  // For example: const signature = crypto.createHmac('sha256', apiKey).update(message + nonce).digest('hex');
  
  const signature = `signed_${message}_${nonce}_${apiKey.slice(-8)}`;
  return {
    message,
    nonce,
    signature,
    timestamp: new Date().toISOString()
  };
}

/**
 * Example database operation function
 */
async function queryDatabase({ query, databaseUrl }) {
  console.log(`\n🗄️  Executing database query...`);
  console.log(`   Query: ${query}`);
  console.log(`   Database URL: ${databaseUrl ? databaseUrl.replace(/:[^:@]*@/, ':****@') : 'NOT PROVIDED'}`);
  
  // In a real scenario, you would connect to the database using databaseUrl
  // For example: const client = new pg.Client({ connectionString: databaseUrl });
  
  return {
    query,
    result: 'Query executed successfully',
    rows: 3
  };
}

/**
 * Main example function
 */
async function main() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🚀 vhsm.exec() Example - Secure Function Execution');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  console.log('This example demonstrates:');
  console.log('  1. Executing functions with automatic env variable injection');
  console.log('  2. Using "@vhsm KEY" syntax to reference encrypted env variables');
  console.log('  3. Automatic memory cleanup of sensitive data\n');
  
  try {
    // Example 1: Sign a message using API_KEY from .env
    console.log('Example 1: Signing a message with API_KEY');
    console.log('─────────────────────────────────────────────');
    
    const signedResult = await exec(
      signMessage,
      {
        message: 'Hello, World!',
        nonce: '123456789',
        apiKey: '@vhsm API_KEY'  // This will be automatically decrypted from .env
      },
      {
        encryptedKeysFile: '.env.keys.encrypted',
        envFile: '.env',
        password: 'password',
      }
    );
    
    console.log('\n✅ Signature created:');
    console.log(`   ${JSON.stringify(signedResult, null, 2)}`);
    
    // Example 2: Query database using DATABASE_URL from .env
    console.log('\n\nExample 2: Querying database with DATABASE_URL');
    console.log('─────────────────────────────────────────────────');
    
    const dbResult = await exec(
      queryDatabase,
      {
        query: 'SELECT * FROM users LIMIT 10',
        databaseUrl: '@vhsm DATABASE_URL'  // This will be automatically decrypted from .env
      },
      {
        encryptedKeysFile: '.env.keys.encrypted',
        envFile: '.env',
        password: 'password',
      }
    );
    
    console.log('\n✅ Database query executed:');
    console.log(`   ${JSON.stringify(dbResult, null, 2)}`);
    
    // Example 3: Mixed parameters (some env vars, some regular)
    console.log('\n\nExample 3: Mixed parameters (env vars + regular values)');
    console.log('───────────────────────────────────────────────────────────');
    
    const mixedResult = await exec(
      async ({ message, secretToken, userId, timestamp }) => {
        console.log(`\n📝 Processing request...`);
        console.log(`   Message: ${message}`);
        console.log(`   Secret Token: ${secretToken ? '***' + secretToken.slice(-4) : 'NOT PROVIDED'}`);
        console.log(`   User ID: ${userId}`);
        console.log(`   Timestamp: ${timestamp}`);
        
        return {
          processed: true,
          messageId: `msg_${userId}_${Date.now()}`
        };
      },
      {
        message: 'User action',
        secretToken: '@vhsm SECRET_TOKEN',  // From .env
        userId: 'user123',                   // Regular value
        timestamp: new Date().toISOString()  // Regular value
      },
      {
        encryptedKeysFile: '.env.keys.encrypted',
        envFile: '.env',
        password: 'password',
      }
    );
    
    console.log('\n✅ Request processed:');
    console.log(`   ${JSON.stringify(mixedResult, null, 2)}`);
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('✨ All examples completed successfully!');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('Note: All sensitive values were automatically cleared from memory');
    console.log('      after function execution.\n');
    
  } catch (error) {
    console.error('\n❌ Error:', error.message);
    if (error.stack) {
      console.error('\nStack trace:');
      console.error(error.stack);
    }
    process.exit(1);
  }
}

// Run the example
main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

