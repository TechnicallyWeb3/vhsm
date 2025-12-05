#!/usr/bin/env node

/**
 * Example demonstrating nested vhsm.exec() calls with ethers.js
 * 
 * This example shows:
 * 1. Loading a wallet from a mnemonic using exec()
 * 2. Getting the wallet address
 * 3. Signing a transaction where the wallet is loaded via another nested exec() call
 * 
 * SECURITY: Before running, you must enable exec via environment variable:
 *   export VHSM_ALLOW_EXEC=true  (or set in .vhsmrc.json)
 * 
 * exec() cannot be enabled programmatically - this is a security feature to prevent
 * malicious code from bypassing admin restrictions.
 */

import { exec } from '../dist/index.js';
import { ethers } from 'ethers';

// Enable exec for this example (in production, set this via environment or config file)
process.env.VHSM_ALLOW_EXEC = 'true';

const execOptions = {
  encryptedKeysFile: '.env.keys.encrypted',
  envFile: '.env',
  password: 'password',
};

/**
 * Load a wallet from a mnemonic phrase
 */
async function loadWallet({ mnemonic }) {
  console.log(`\n🔑 Loading wallet from mnemonic...`);
  
  if (!mnemonic) {
    throw new Error('Mnemonic is required');
  }
  
  // Validate mnemonic
  if (!ethers.Mnemonic.isValidMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase');
  }
  
  // Create wallet from mnemonic
  const wallet = ethers.Wallet.fromPhrase(mnemonic);
  
  console.log(`   ✅ Wallet loaded`);
  console.log(`   📍 Address: ${wallet.address}`);
  
  return wallet;
}

/**
 * Get wallet address
 */
async function getWalletAddress({ wallet }) {
  console.log(`\n📍 Getting wallet address...`);
  
  const address = wallet.address;
  console.log(`   Address: ${address}`);
  
  return {
    address,
    wallet: wallet  // Return wallet for further use
  };
}

/**
 * Sign a transaction message
 */
async function signTransaction({ wallet, to, value, message }) {
  console.log(`\n✍️  Signing transaction message...`);
  console.log(`   To: ${to}`);
  console.log(`   Value: ${value ? ethers.formatEther(value) + ' ETH' : '0 ETH'}`);
  console.log(`   Message: ${message || 'Transaction data'}`);
  
  // Create a transaction message to sign
  const txMessage = JSON.stringify({
    to: to,
    value: value ? value.toString() : '0',
    message: message || 'Transaction',
    from: wallet.address,
    timestamp: Date.now()
  });
  
  // Sign the message
  const signature = await wallet.signMessage(txMessage);
  
  console.log(`   ✅ Transaction message signed`);
  console.log(`   📝 Signature: ${signature.slice(0, 66)}...`);
  
  return {
    transaction: {
      to: to,
      value: value || 0,
      message: message,
      from: wallet.address
    },
    signature: signature,
    signedMessage: txMessage
  };
}

/**
 * Main example function
 */
async function main() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🚀 Nested vhsm.exec() Example with ethers.js');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  console.log('This example demonstrates:');
  console.log('  1. Loading a wallet from CRYPTO_WALLET mnemonic using exec()');
  console.log('  2. Getting the wallet address');
  console.log('  3. Signing a transaction with nested exec() for wallet loading\n');
  
  try {
    // Example 1: Load wallet from mnemonic using exec()
    console.log('Example 1: Loading wallet from CRYPTO_WALLET mnemonic');
    console.log('──────────────────────────────────────────────────────────');
    
    const walletResult = await exec(
      loadWallet,
      {
        mnemonic: '@vhsm CRYPTO_WALLET'  // Automatically decrypted from .env
      },
      execOptions
    );
    
    console.log(`\n✅ Wallet loaded successfully!`);
    console.log(`   Address: ${walletResult.address}`);
    
    // Example 2: Get wallet address
    console.log('\n\nExample 2: Getting wallet address');
    console.log('────────────────────────────────────');
    
    const addressResult = await exec(
      getWalletAddress,
      {
        wallet: walletResult
      },
      execOptions
    );
    
    console.log(`\n✅ Address retrieved: ${addressResult.address}`);
    
    // Example 3: Nested exec() - Sign transaction with wallet loaded via nested exec()
    console.log('\n\nExample 3: Nested exec() - Signing transaction');
    console.log('─────────────────────────────────────────────────────────');
    console.log('   Loading wallet via nested exec() and using it to sign...\n');
    
    // This demonstrates nested execution:
    // The 'wallet' parameter is the result of another exec() call
    const signedTxResult = await exec(
      signTransaction,
      {
        // Nested exec() - load wallet from mnemonic first
        wallet: await exec(
          loadWallet,
          {
            mnemonic: '@vhsm CRYPTO_WALLET'
          },
          execOptions
        ),
        to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5',  // Example address
        value: ethers.parseEther('0.1'),  // 0.1 ETH
        message: 'Transfer 0.1 ETH'
      },
      execOptions
    );
    
    console.log(`\n✅ Transaction signed successfully!`);
    console.log(`   From: ${signedTxResult.transaction.from}`);
    console.log(`   To: ${signedTxResult.transaction.to}`);
    console.log(`   Value: ${ethers.formatEther(signedTxResult.transaction.value)} ETH`);
    console.log(`   Signature length: ${signedTxResult.signature.length} bytes`);
    
    // Example 4: Complete flow - nested exec() in one go
    console.log('\n\nExample 4: Complete nested execution in one call');
    console.log('────────────────────────────────────────────────────────────');
    console.log('   Loading wallet and signing in a single nested exec() call...\n');
    
    const completeResult = await exec(
      async ({ walletPromise, to, value }) => {
        // The walletPromise will be resolved before this function runs
        const wallet = await walletPromise;
        
        console.log(`   📍 Using wallet: ${wallet.address}`);
        
        return await signTransaction({
          wallet,
          to,
          value,
          message: 'Nested exec transaction'
        });
      },
      {
        // Pass a Promise (from nested exec) as a parameter
        walletPromise: exec(
          loadWallet,
          {
            mnemonic: '@vhsm CRYPTO_WALLET'
          },
          execOptions
        ),
        to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb5',
        value: ethers.parseEther('0.05'),  // 0.05 ETH
        message: 'Transfer 0.05 ETH'
      },
      execOptions
    );
    
    console.log(`\n✅ Complete nested execution successful!`);
    console.log(`   Transaction signed: ${completeResult.signature.slice(0, 66)}...`);
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('✨ All nested execution examples completed successfully!');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('Key takeaways:');
    console.log('  • exec() can load sensitive data (mnemonics) from env vars');
    console.log('  • exec() calls can be nested - one exec() result can be');
    console.log('    used as input to another exec() call');
    console.log('  • Promises returned from exec() are automatically resolved');
    console.log('  • All sensitive data is automatically cleared from memory\n');
    
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

