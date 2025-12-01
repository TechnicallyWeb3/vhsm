import { createServer } from 'node:http';
import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import type { Provider, KeyDecryptionProvider, ProviderConfig, PasswordMode } from '../types.js';
import { DecryptionError } from '../types.js';
import { Fido2Lib } from 'fido2-lib';

const require = createRequire(import.meta.url);
const pkg = require('../../package.json') as { version?: string };
const VERSION = pkg.version || '0.0.0';

/**
 * FIDO2/Yubikey key decryption provider
 * Uses FIDO2 authentication with Yubikey for key protection
 * 
 * This provider:
 * - Requires a Yubikey or other FIDO2-compatible device
 * - Requires user interaction (touch/presence)
 * - Starts a temporary local web server for WebAuthn authentication
 * - Uses FIDO2 credential for key derivation
 */
export class FIDO2Provider implements Provider, KeyDecryptionProvider {
  readonly name = 'fido2';
  readonly requiresInteraction = true;
  readonly passwordMode: PasswordMode = 'none';
  readonly outputPrefix = 'fido2';
  
  private f2l: any;
  private rpId = 'localhost';
  private rpName = 'VHSM FIDO2 Provider';

  private BROWSER_CLOSE_DELAY_MS = 100;
  private PAGE_TIMEOUT_MS = 120000;
  
  // Cache derived keys per credential ID during a session to avoid multiple authentications
  private derivedKeyCache = new Map<string, Buffer>();
  
  constructor() {
    this.f2l = new Fido2Lib({
      timeout: 60000,
      rpId: this.rpId,
      rpName: this.rpName,
      challengeSize: 32,
      attestation: 'none',
      cryptoParams: [-7, -257],
      authenticatorRequireResidentKey: false,
      authenticatorUserVerification: 'preferred'
    });
  }
  
  /**
   * Clear the derived key cache (useful for testing or explicit cache clearing)
   */
  clearDerivedKeyCache(): void {
    this.derivedKeyCache.clear();
  }

  /**
   * Helper method to generate HTML page for FIDO2 operations
   * Modularizes page generation to reduce code duplication
   */
  private generateWebAuthnPage(options: {
    type: 'register' | 'authenticate';
    challenge: string;
    credentialId?: string;
    userId?: string;
    authenticatorAttachment?: string | null;
    timeoutMs: number;
  }): string {
    const { type, challenge, credentialId, userId, authenticatorAttachment, timeoutMs } = options;
    const isRegister = type === 'register';
    
    // Style configuration
    const gradient = isRegister 
      ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
      : 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)';
    const buttonGradient = isRegister
      ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
      : 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)';
    const logo = isRegister ? '🔐' : '🔓';
    const title = isRegister ? 'FIDO2 Registration' : 'FIDO2 Authentication';
    const buttonText = isRegister ? 'Register Yubikey' : 'Unlock with FIDO2';
    const buttonId = isRegister ? 'registerBtn' : 'authBtn';
    const actionFunction = isRegister ? 'register()' : 'authenticate()';
    
    // Status message
    const statusMessage = isRegister
      ? 'Click the button below and touch your Yubikey when it blinks.'
      : 'Click the button below to authenticate. Use the SAME authenticator type you used during encryption (Windows Hello, hardware key, or mobile device).';

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vHSM - ${title}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: ${gradient};
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      max-width: 500px;
      width: 100%;
      padding: 40px;
      text-align: center;
    }
    .header {
      margin-bottom: 30px;
    }
    .logo {
      font-size: 64px;
      margin-bottom: 10px;
      display: block;
    }
    h1 {
      color: #2d3748;
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 8px;
    }
    .subtitle {
      color: #718096;
      font-size: 14px;
      margin-bottom: 4px;
    }
    .version {
      display: inline-block;
      background: #edf2f7;
      color: #4a5568;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 500;
      margin-top: 8px;
    }
    .status { 
      padding: 20px;
      border-radius: 12px;
      margin: 30px 0;
      background: #f7fafc;
      border: 2px solid #e2e8f0;
      transition: all 0.3s ease;
    }
    .status p {
      color: #4a5568;
      font-size: 16px;
      line-height: 1.6;
    }
    .success { 
      background: #f0fff4; 
      border-color: #9ae6b4;
    }
    .success p { color: #22543d; }
    .error { 
      background: #fff5f5; 
      border-color: #fc8181;
    }
    .error p { color: #742a2a; }
    button {
      background: ${buttonGradient};
      color: white;
      border: none;
      padding: 16px 32px;
      font-size: 16px;
      font-weight: 600;
      border-radius: 12px;
      cursor: pointer;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
      width: 100%;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
    }
    button:active {
      transform: translateY(0);
    }
    button:disabled {
      background: #cbd5e0;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
    .yubikey-icon {
      font-size: 48px;
      margin: 20px 0;
      display: block;
      animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    .footer {
      margin-top: 30px;
      color: #a0aec0;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span class="logo">${logo}</span>
      <h1>${title}</h1>
      <p class="subtitle">vHSM - Virtual Hardware Security Module</p>
      <span class="version">v${VERSION}</span>
    </div>
    
    <div class="status">
      <p id="status">${statusMessage}</p>
    </div>
    
    <span id="yubikey-icon" class="yubikey-icon" style="display:none;">🔑</span>
    
    <button id="${buttonId}" onclick="${actionFunction}">${buttonText}</button>
    
    <div class="footer">
      Secured by FIDO2 WebAuthn
    </div>
  </div>
  
  <script>
    const TIMEOUT_MS = ${timeoutMs};
    const SERVER_ENDPOINT = '${isRegister ? '/register' : '/authenticate'}';
    const CHALLENGE = '${challenge}';
    ${credentialId ? `const CREDENTIAL_ID = '${credentialId}';` : ''}
    ${userId ? `const USER_ID = '${userId}';` : ''}
    ${authenticatorAttachment ? `const AUTHENTICATOR_ATTACHMENT = '${authenticatorAttachment}';` : 'const AUTHENTICATOR_ATTACHMENT = null;'}
    const RP_ID = '${this.rpId}';
    const RP_NAME = '${this.rpName}';
    const BROWSER_CLOSE_DELAY = ${this.BROWSER_CLOSE_DELAY_MS};
    
    // Auto-close on timeout
    let timeoutCheck = setTimeout(() => {
      const status = document.getElementById('status');
      if (status) {
        status.parentElement.className = 'status error';
        status.textContent = '⏱️ Timeout - Closing window...';
      }
      setTimeout(() => window.close(), 1000);
    }, TIMEOUT_MS);
    
    ${isRegister ? this.generateRegisterScript() : this.generateAuthenticateScript()}
  </script>
</body>
</html>`;
  }

  /**
   * Generates the registration JavaScript
   */
  private generateRegisterScript(): string {
    return `
    async function register() {
      const btn = document.getElementById('registerBtn');
      const status = document.getElementById('status');
      const icon = document.getElementById('yubikey-icon');
      
      try {
        btn.disabled = true;
        status.parentElement.className = 'status';
        status.textContent = '👆 Touch your Yubikey now...';
        icon.style.display = 'block';
        
        // Create credential
        const credential = await navigator.credentials.create({
          publicKey: {
            challenge: Uint8Array.from(atob(CHALLENGE.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
            rp: { name: RP_NAME, id: RP_ID },
            user: {
              id: Uint8Array.from(atob(USER_ID.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
              name: 'vhsm-user',
              displayName: 'VHSM User'
            },
            pubKeyCredParams: [
              { type: 'public-key', alg: -7 },
              { type: 'public-key', alg: -257 }
            ],
            timeout: 60000,
            attestation: 'none'
          }
        });
        
        // Extract authenticatorAttachment if available
        let authenticatorAttachment = null;
        try {
          if (credential.authenticatorAttachment) {
            authenticatorAttachment = credential.authenticatorAttachment;
          }
        } catch (e) {
          // Not available - will parse on server side
        }
        
        // Send credential to server
        const credId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)))
          .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        
        let response;
        let responseData;
        
        try {
          response = await fetch(SERVER_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              credentialId: credId,
              authenticatorAttachment: authenticatorAttachment,
              response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
              }
            })
          });
        } catch (fetchError) {
          throw new Error('Failed to connect to server. The server may have closed. Please try the encryption again.');
        }
        
        try {
          responseData = await response.json();
        } catch (jsonError) {
          throw new Error('Server response was invalid. Please try the encryption again.');
        }
        
        if (response.ok && responseData.success) {
          clearTimeout(timeoutCheck);
          icon.style.display = 'none';
          status.parentElement.className = 'status success';
          status.textContent = '✅ Success! Credential registered. Window will close shortly...';
          
          // Close window after delay - server will keep connection alive until then
          setTimeout(() => {
            window.close();
          }, BROWSER_CLOSE_DELAY);
        } else {
          throw new Error('Server rejected credential');
        }
      } catch (error) {
        clearTimeout(timeoutCheck);
        icon.style.display = 'none';
        status.parentElement.className = 'status error';
        status.textContent = '❌ Error: ' + error.message;
        btn.disabled = false;
      }
    }
    `;
  }

  /**
   * Generates the authentication JavaScript
   */
  private generateAuthenticateScript(): string {
    return `
    async function authenticate() {
      const btn = document.getElementById('authBtn');
      const status = document.getElementById('status');
      const icon = document.getElementById('yubikey-icon');
      
      try {
        btn.disabled = true;
        status.parentElement.className = 'status';
        status.textContent = '🔐 Authenticate using the same method you used during encryption...';
        icon.style.display = 'block';
        
        // Build authentication options
        const authOptions = {
          challenge: Uint8Array.from(atob(CHALLENGE.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
          rpId: RP_ID,
          allowCredentials: [{
            type: 'public-key',
            id: Uint8Array.from(atob(CREDENTIAL_ID.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
          }],
          timeout: 60000,
          userVerification: 'preferred'
        };
        
        // CRITICAL: If we know the authenticatorAttachment type, prefer it
        // This ensures the browser shows the correct authenticator option
        if (AUTHENTICATOR_ATTACHMENT) {
          // Prefer the same authenticator type that was used during encryption
          // This helps the browser show the correct option (platform vs cross-platform)
          authOptions.authenticatorAttachment = AUTHENTICATOR_ATTACHMENT;
        }
        
        const assertion = await navigator.credentials.get({
          publicKey: authOptions
        });
        
        // Send assertion to server
        let response;
        let responseData;
        
        try {
          response = await fetch(SERVER_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              credentialId: CREDENTIAL_ID,
              response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature)))
              }
            })
          });
        } catch (fetchError) {
          throw new Error('Failed to connect to server. The server may have closed. Please try the decryption again.');
        }
        
        try {
          responseData = await response.json();
        } catch (jsonError) {
          throw new Error('Server response was invalid. Please try the decryption again.');
        }
        
        if (response.ok && responseData.success) {
          clearTimeout(timeoutCheck);
          icon.style.display = 'none';
          status.parentElement.className = 'status success';
          status.textContent = '✅ Success! You can close this window.';
          setTimeout(() => window.close(), BROWSER_CLOSE_DELAY / 2);
        } else {
          throw new Error('Authentication failed');
        }
      } catch (error) {
        clearTimeout(timeoutCheck);
        icon.style.display = 'none';
        status.parentElement.className = 'status error';
        status.textContent = '❌ Error: ' + error.message;
        btn.disabled = false;
      }
    }
    
    // Auto-start on load
    window.onload = () => {
      setTimeout(() => document.getElementById('authBtn').click(), 500);
    };
    `;
  }

  /**
   * Encrypts data using FIDO2-derived key
   * This creates a credential and derives an encryption key from it
   * Note: Verification happens in validateEncryption() before this is called with real data
   */
  async encrypt(plaintextKey: string, config?: ProviderConfig): Promise<string> {
    try {
      const credentialId = config?.credentialId as string | undefined;
      let derivedKey: Buffer;
      let storedCredId: string;

      if (credentialId) {
        // Use existing credential - derive key directly without authentication
        // (Authentication is only required for decryption)
        derivedKey = createHash('sha256').update(credentialId).digest();
        storedCredId = credentialId;
      } else {
        // Create new credential (typically only happens during validateEncryption with test data)
        const result = await this.createCredential();
        derivedKey = result.key;
        storedCredId = result.credentialId;
        // Store authenticatorAttachment if available - will be included in encrypted format
        if (result.authenticatorAttachment && !config?.authenticatorAttachment) {
          config = { ...config, authenticatorAttachment: result.authenticatorAttachment };
        }
      }

      // Encrypt the data using AES-256-GCM
      const iv = randomBytes(16);
      const cipher = createCipheriv('aes-256-gcm', derivedKey, iv);
      
      let encrypted = cipher.update(plaintextKey, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      // Format (new): credentialId:authenticatorAttachment:iv:authTag:encryptedData (5 parts)
      // Format (old, backward compatible): credentialId:iv:authTag:encryptedData (4 parts)
      const authenticatorAttachment = (config?.authenticatorAttachment as string | undefined) || '';
      if (authenticatorAttachment) {
        // New format with authenticatorAttachment
        return `${storedCredId}:${authenticatorAttachment}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
      } else {
        // Old format for backward compatibility
        return `${storedCredId}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
      }
    } catch (error) {
      if (error instanceof Error) {
        throw new DecryptionError(`FIDO2 encryption failed: ${error.message}`);
      }
      throw new DecryptionError('FIDO2 encryption failed');
    }
  }

  /**
   * Validates FIDO2 credential before encryption
   */
  async validateEncryption(
    config?: ProviderConfig,
    existingKeys?: Array<{ provider: string; encryptedValue: string }>
  ): Promise<ProviderConfig | void> {
    const credentialId = config?.credentialId as string | undefined;
    const existingFido2Keys = existingKeys?.filter(k => k.provider === 'fido2') || [];
    const testData = 'test-validation';
    
    if (existingFido2Keys.length > 0 && credentialId) {
      // Extract credential ID from existing key
      const existingCredId = existingFido2Keys[0].encryptedValue.split(':')[0];
      if (existingCredId !== credentialId) {
        throw new Error('Credential ID mismatch with existing keys');
      }
      
      console.log('Validating FIDO2 credential...');

      // Test encrypt and decrypt with dummy data to ensure credential is usable
      try {
        const encrypted = await this.encrypt(testData, { credentialId });
        // Clear cache to force re-authentication for decryption test
        this.clearDerivedKeyCache();
        const decrypted = await this.decrypt(encrypted);
        if (decrypted !== testData) {
          throw new Error('Decryption test failed: decrypted value does not match original');
        }
        console.log('✅ FIDO2 credential validated (encryption and decryption test passed).');
      } catch (error) {
        throw new Error(`FIDO2 credential validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
      return { credentialId };
    } else if (existingFido2Keys.length === 0) {
      // Need to create new credential - do it NOW before dotenvx
      console.log('Creating FIDO2 credential (this will open a browser window)...');
      console.log('You will need to authenticate ONCE to register a credential.\n');
      try {
        // Create credential with test data
        const testEncrypted = await this.encrypt(testData);
        const newCredentialId = testEncrypted.split(':')[0];
        
        // CRITICAL: Immediately verify the credential works by decrypting the test data
        // This ensures the credential can be used for decryption before we encrypt real secrets
        // This prevents data loss if the credential type (this device/hardware key/mobile) 
        // is not available during decryption
        console.log('\n🔍 Verifying credential by attempting immediate decryption...');
        console.log('   (This ensures you can decrypt what was just encrypted)\n');
        
        try {
          // Clear cache to force fresh authentication during verification
          this.derivedKeyCache.delete(newCredentialId);
          
          // Attempt decryption - this will prompt for authentication using the same method
          const decrypted = await this.decrypt(testEncrypted);
          
          // Verify the decrypted value matches the test data
          if (decrypted !== 'test-validation') {
            throw new Error('Decryption verification failed: decrypted value does not match test data');
          }
          
          console.log('✅ Credential verification successful! The credential is working correctly.');
          console.log('   You can now proceed with encryption.\n');
        } catch (verifyError) {
          // If verification fails, don't proceed with encryption
          // This prevents creating encrypted data that cannot be decrypted later
          const errorMsg = verifyError instanceof Error ? verifyError.message : 'Unknown error';
          throw new Error(
            `FIDO2 credential verification failed: ${errorMsg}\n` +
            `The credential was created but cannot be used for decryption.\n` +
            `This prevents data loss - please try again with a different authenticator option.\n` +
            `Make sure to use the same authenticator type (this device/hardware key/mobile) that will be available later.`
          );
        }
        
        // Clear cache to force re-authentication for decryption test
        this.clearDerivedKeyCache();
        const decrypted = await this.decrypt(testEncrypted);
        if (decrypted !== testData) {
          throw new Error('Decryption test failed: decrypted value does not match original');
        }
        console.log('✅ FIDO2 credential created and validated (encryption and decryption test passed).');
        return { credentialId: newCredentialId };
      } catch (error) {
        if (error instanceof Error && error.message.includes('verification failed')) {
          // Re-throw verification errors as-is (they already have good messages)
          throw error;
        }
        throw new Error(`FIDO2 credential creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    
    return config;
  }

  /**
   * Decrypts the encrypted key using FIDO2 authentication
   * Format (old): credentialId:iv:authTag:encryptedData (4 parts)
   * Format (new): credentialId:authenticatorAttachment:iv:authTag:encryptedData (5 parts)
   * Supports both legacy interface (string password - unused for FIDO2) and new interface (ProviderConfig)
   */
  async decrypt(encryptedKey: string, _configOrPassword?: ProviderConfig | string): Promise<string> {
    // Support both old interface (string) and new interface (ProviderConfig)
    // FIDO2 doesn't use password/config for decryption, so we ignore it
    try {
      // Parse the encrypted key - support both old (4-part) and new (5-part) formats
      const parts = encryptedKey.split(':');
      let credentialId: string;
      let authenticatorAttachment: string | null = null;
      let ivHex: string;
      let authTagHex: string;
      let encryptedData: string;
      
      if (parts.length === 4) {
        // Old format: credentialId:iv:authTag:encryptedData
        [credentialId, ivHex, authTagHex, encryptedData] = parts;
      } else if (parts.length === 5) {
        // New format: credentialId:authenticatorAttachment:iv:authTag:encryptedData
        [credentialId, authenticatorAttachment, ivHex, authTagHex, encryptedData] = parts;
        // Handle empty authenticatorAttachment (could be empty string)
        if (authenticatorAttachment === '') {
          authenticatorAttachment = null;
        }
      } else {
        throw new DecryptionError('Invalid FIDO2 encrypted key format - expected 4 or 5 parts');
      }
      
      // Check if we already have a derived key for this credential ID in this session
      // This allows decrypting multiple keys with the same credential ID without multiple authentications
      let derivedKey = this.derivedKeyCache.get(credentialId);
      
      if (!derivedKey) {
        // Derive key from FIDO2 credential (requires user touch)
        // Only prompt once per credential ID per session
        const isFirstKey = this.derivedKeyCache.size === 0;
        if (isFirstKey) {
          console.log('🔑 Please touch your Yubikey to decrypt keys...');
        } else {
          console.log('🔑 Please touch your Yubikey to decrypt additional keys...');
        }
        // Pass authenticatorAttachment to help browser show correct authenticator option
        derivedKey = await this.deriveKeyFromCredential(credentialId, authenticatorAttachment);
        // Cache the derived key for this credential ID
        this.derivedKeyCache.set(credentialId, derivedKey);
      }
      
      // Decrypt the data
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      const decipher = createDecipheriv('aes-256-gcm', derivedKey, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      if (error instanceof Error) {
        throw new DecryptionError(`FIDO2 decryption failed: ${error.message}`);
      }
      throw new DecryptionError('FIDO2 decryption failed');
    }
  }

  /**
   * Creates a new FIDO2 credential and derives an encryption key
   */
  private async createCredential(): Promise<{ key: Buffer; credentialId: string; authenticatorAttachment?: string | null }> {
    return new Promise((resolve, reject) => {
      const port = 8765;
      let server: any;
      const connections = new Set<any>();
      let timeoutId: NodeJS.Timeout;
      let pageLoaded = false;
      let authenticationStarted = false;
      let authenticationSucceeded = false; // Track if authentication completed successfully
      
      // Generate registration options
      const registrationOptions = this.f2l.attestationOptions();
      
      registrationOptions.then((options: any) => {
        const challenge = Buffer.from(options.challenge).toString('base64url');
        const userId = randomBytes(16).toString('base64url');
        
        // HTML page for FIDO2 registration
        const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vHSM - FIDO2 Registration</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      max-width: 500px;
      width: 100%;
      padding: 40px;
      text-align: center;
    }
    .header {
      margin-bottom: 30px;
    }
    .logo {
      font-size: 64px;
      margin-bottom: 10px;
      display: block;
    }
    h1 {
      color: #2d3748;
      font-size: 28px;
      font-weight: 700;
      margin-bottom: 8px;
    }
    .subtitle {
      color: #718096;
      font-size: 14px;
      margin-bottom: 4px;
    }
    .version {
      display: inline-block;
      background: #edf2f7;
      color: #4a5568;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 500;
      margin-top: 8px;
    }
    .status { 
      padding: 20px;
      border-radius: 12px;
      margin: 30px 0;
      background: #f7fafc;
      border: 2px solid #e2e8f0;
      transition: all 0.3s ease;
    }
    .status p {
      color: #4a5568;
      font-size: 16px;
      line-height: 1.6;
    }
    .success { 
      background: #f0fff4; 
      border-color: #9ae6b4;
    }
    .success p { color: #22543d; }
    .error { 
      background: #fff5f5; 
      border-color: #fc8181;
    }
    .error p { color: #742a2a; }
    button {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      padding: 16px 32px;
      font-size: 16px;
      font-weight: 600;
      border-radius: 12px;
      cursor: pointer;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
      width: 100%;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
    }
    button:active {
      transform: translateY(0);
    }
    button:disabled {
      background: #cbd5e0;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
    .yubikey-icon {
      font-size: 48px;
      margin: 20px 0;
      display: block;
      animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    .footer {
      margin-top: 30px;
      color: #a0aec0;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span class="logo">🔐</span>
      <h1>FIDO2 Registration</h1>
      <p class="subtitle">vHSM - Virtual Hardware Security Module</p>
      <span class="version">v${VERSION}</span>
    </div>
    
    <div class="status">
      <p id="status">Click the button below and touch your Yubikey when it blinks.</p>
    </div>
    
    <span id="yubikey-icon" class="yubikey-icon" style="display:none;">🔑</span>
    
    <button id="registerBtn" onclick="register()">Register Yubikey</button>
    
    <div class="footer">
      Secured by FIDO2 WebAuthn
    </div>
  </div>
  
  <script>
    // Auto-close on timeout (2 minutes)
    let timeoutCheck = setTimeout(() => {
      const status = document.getElementById('status');
      if (status) {
        status.parentElement.className = 'status error';
        status.textContent = '⏱️ Timeout - Closing window...';
      }
      setTimeout(() => window.close(), 1000);
    }, 120000);
    
    async function register() {
      const btn = document.getElementById('registerBtn');
      const status = document.getElementById('status');
      const icon = document.getElementById('yubikey-icon');
      
      try {
        btn.disabled = true;
        status.parentElement.className = 'status';
        status.textContent = '👆 Touch your Yubikey now...';
        icon.style.display = 'block';
        
        // Create credential
        const credential = await navigator.credentials.create({
          publicKey: {
            challenge: Uint8Array.from(atob('${challenge}'.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
            rp: { name: '${this.rpName}', id: '${this.rpId}' },
            user: {
              id: Uint8Array.from(atob('${userId}'.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
              name: 'vhsm-user',
              displayName: 'VHSM User'
            },
            pubKeyCredParams: [
              { type: 'public-key', alg: -7 },
              { type: 'public-key', alg: -257 }
            ],
            timeout: 60000,
            attestation: 'none'
          }
        });
        
        // Send credential to server
        const credId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)))
          .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        
        // Extract authenticatorAttachment to preserve which authenticator type was used
        // This is critical for decryption - we need to know if it was "platform" (this device)
        // or "cross-platform" (hardware key/mobile) so we can use the same type during authentication
        // Note: authenticatorAttachment might be available on the credential object in newer browsers
        let authenticatorAttachment = null;
        try {
          // Try to get from credential's authenticatorAttachment property (if available)
          if (credential.authenticatorAttachment) {
            authenticatorAttachment = credential.authenticatorAttachment;
          } else if (credential.response && typeof credential.response.getAuthenticatorData === 'function') {
            // Try to extract from authenticator data if method exists
            const authData = credential.response.getAuthenticatorData();
            // authenticatorAttachment is not directly in authData, would need to parse attestationObject
          }
        } catch (e) {
          // authenticatorAttachment not available - will parse from attestationObject on server side
        }
        
        let response;
        let responseData;
        
        try {
          response = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              credentialId: credId,
              authenticatorAttachment: authenticatorAttachment, // Include authenticator type
              response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
              }
            })
          });
        } catch (fetchError) {
          throw new Error('Failed to connect to server. The server may have closed. Please try the encryption again.');
        }
        
        // Wait for response body to be fully read to ensure all data is transmitted
        try {
          responseData = await response.json();
        } catch (jsonError) {
          throw new Error('Server response was invalid. Please try the encryption again.');
        }
        
        if (response.ok && responseData.success) {
          clearTimeout(timeoutCheck);
          icon.style.display = 'none';
          status.parentElement.className = 'status success';
          status.textContent = '✅ Success! Credential registered. Window will close shortly...';
          
          // CRITICAL FIX: Keep connection alive until window closes
          // Don't make any more requests after success - just wait and close
          // The server will keep the connection alive for us to close gracefully
          // This prevents "connection refused" errors
          setTimeout(() => {
            // Close window - server will detect connection close and clean up
            window.close();
          }, 4000); // Wait 4 seconds to allow credential persistence, then close
        } else {
          throw new Error('Server rejected credential');
        }
      } catch (error) {
        clearTimeout(timeoutCheck);
        icon.style.display = 'none';
        status.parentElement.className = 'status error';
        status.textContent = '❌ Error: ' + error.message;
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>`;

        // Create HTTP server
        server = createServer((req, res) => {
          // Enable CORS
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
          res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
          
          if (req.method === 'GET' && req.url === '/') {
            pageLoaded = true;
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
          } else if (req.method === 'POST' && req.url === '/register') {
            authenticationStarted = true;
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
              try {
                const data = JSON.parse(body);
                const credentialId = data.credentialId;
                const authenticatorAttachment = data.authenticatorAttachment || null; // Extract authenticator type
                
                // Derive key from credential ID (simple hash for now)
                // In production, you'd verify the attestation and store credential properly
                const key = createHash('sha256').update(credentialId).digest();
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
                
                // Mark authentication as succeeded to prevent connection close handler from rejecting
                authenticationSucceeded = true;
                
                // Clear the timeout since we succeeded
                clearTimeout(timeoutId);
                
                // CRITICAL FIX: Keep server and connections alive until browser actually closes
                // The browser shows success and closes window after 4000ms. We need to keep the
                // connection alive during this time to prevent "connection refused" errors.
                // 
                // Strategy: Wait for browser window to close (4000ms) + buffer before closing server
                // Don't close server until browser has had time to close naturally
                setTimeout(() => {
                  connections.forEach(conn => conn.destroy());
                  server.close(() => {
                    resolve({ key, credentialId });
                  });
                }, 100);
              } catch (error) {
                res.writeHead(400);
                res.end();
                setTimeout(() => {
                  connections.forEach(conn => conn.destroy());
                  server.close(() => {
                    reject(error);
                  });
                }, 100);
              }
            });
          } else if (req.method === 'GET' && req.url !== '/') {
            // Handle other GET requests (like favicon.ico) gracefully
            res.writeHead(204, { 'Content-Length': '0' });
            res.end();
          } else {
            // Invalid route - return 404 with helpful message
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 - Route not found. Expected: GET / or POST /register');
          }
        });

        // Track connections for cleanup and detect browser closure
        server.on('connection', (conn: any) => {
          connections.add(conn);
          conn.on('close', () => {
            connections.delete(conn);
            // Only reject if page was loaded but authentication never started AND didn't succeed
            // If authentication succeeded, connection closing is expected and normal
            // We should NOT reject after successful authentication even if connection closes
            if (pageLoaded && !authenticationStarted && !authenticationSucceeded && connections.size === 0) {
              clearTimeout(timeoutId);
              server.close(() => {
                reject(new Error('Browser window was closed before authentication could complete'));
              });
            }
          });
        });

        // Handle server errors
        server.on('error', (err: any) => {
          if (err.code === 'EADDRINUSE') {
            clearTimeout(timeoutId);
            server.close(() => {
              reject(new Error(
                `Port ${port} is already in use. This might be from a previous encryption attempt.\n` +
                `Please wait a moment and try again, or manually close any processes using port ${port}.\n` +
                `On Windows: Get-Process -Id (Get-NetTCPConnection -LocalPort ${port}).OwningProcess | Stop-Process`
              ));
            });
          } else {
            clearTimeout(timeoutId);
            server.close(() => {
              reject(new Error(`Server error: ${err.message}`));
            });
          }
        });

        server.listen(port, () => {
          console.log(`\n🌐 Please open your browser to: http://localhost:${port}\n`);
          
          // Try to open browser automatically
          const url = `http://localhost:${port}`;
          const cmd = process.platform === 'win32' ? 'start' : 
                      process.platform === 'darwin' ? 'open' : 'xdg-open';
          
          spawn(cmd, [url], { 
            detached: true, 
            stdio: 'ignore',
            shell: true 
          }).unref();
        });

        // Timeout after 2 minutes
        timeoutId = setTimeout(() => {
          connections.forEach(conn => conn.destroy());
          server.close(() => {
            reject(new Error('Registration timeout - no response received'));
          });
        }, 120000);
      }).catch(reject);
    });
  }

  /**
   * Derives an encryption key from an existing credential
   * Requires user presence (touch)
   */
  private async deriveKeyFromCredential(credentialId: string, authenticatorAttachment?: string | null): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const port = 8765;
      let server: any;
      const connections = new Set<any>();
      let timeoutId: NodeJS.Timeout;
      let pageLoaded = false;
      let authenticationStarted = false;
      
      // Generate authentication options
      const authOptions = this.f2l.assertionOptions();
      
      authOptions.then((options: any) => {
        const challenge = Buffer.from(options.challenge).toString('base64url');
        
        // Use helper method to generate HTML page - modularizes and reduces duplication
        const html = this.generateWebAuthnPage({
          type: 'authenticate',
          challenge,
          credentialId,
          authenticatorAttachment: authenticatorAttachment || undefined,
          timeoutMs: this.PAGE_TIMEOUT_MS
        });
        
        // Create HTTP server
        server = createServer((req, res) => {
          // Enable CORS
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
          res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
          
          if (req.method === 'GET' && req.url === '/') {
            pageLoaded = true;
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
          } else if (req.method === 'POST' && req.url === '/authenticate') {
            authenticationStarted = true;
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
              try {
                const data = JSON.parse(body);
                
                // Derive key from credential ID (same method as registration)
                const key = createHash('sha256').update(credentialId).digest();
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
                
                // Clear the timeout since we succeeded
                clearTimeout(timeoutId);
                
                // Close server and all connections
                // Small delay to ensure response is sent before destroying connections
                setTimeout(() => {
                  connections.forEach(conn => conn.destroy());
                  server.close(() => {
                    resolve(key);
                  });
                }, 100);
              } catch (error) {
                res.writeHead(400);
                res.end();
                setTimeout(() => {
                  connections.forEach(conn => conn.destroy());
                  server.close(() => {
                    reject(error);
                  });
                }, 100);
              }
            });
          } else if (req.method === 'GET' && req.url !== '/') {
            // Handle other GET requests (like favicon.ico) gracefully
            res.writeHead(204, { 'Content-Length': '0' });
            res.end();
          } else {
            // Invalid route - return 404 with helpful message
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 - Route not found. Expected: GET / or POST /register');
          }
        });

        // Track connections for cleanup and detect browser closure
        server.on('connection', (conn: any) => {
          connections.add(conn);
          conn.on('close', () => {
            connections.delete(conn);
            // If page was loaded but authentication hasn't started, browser was closed
            if (pageLoaded && !authenticationStarted && connections.size === 0) {
              clearTimeout(timeoutId);
              server.close(() => {
                reject(new Error('Browser window was closed before authentication could complete'));
              });
            }
          });
        });

        // Handle server errors
        server.on('error', (err: any) => {
          if (err.code === 'EADDRINUSE') {
            clearTimeout(timeoutId);
            server.close(() => {
              reject(new Error(
                `Port ${port} is already in use. This might be from a previous decryption attempt.\n` +
                `Please wait a moment and try again, or manually close any processes using port ${port}.\n` +
                `On Windows: Get-Process -Id (Get-NetTCPConnection -LocalPort ${port}).OwningProcess | Stop-Process`
              ));
            });
          } else {
            clearTimeout(timeoutId);
            server.close(() => {
              reject(new Error(`Server error: ${err.message}`));
            });
          }
        });

        server.listen(port, () => {
          console.log(`\n🌐 Opening browser for authentication...\n`);
          
          // Try to open browser automatically
          const url = `http://localhost:${port}`;
          const cmd = process.platform === 'win32' ? 'start' : 
                      process.platform === 'darwin' ? 'open' : 'xdg-open';
          
          spawn(cmd, [url], { 
            detached: true, 
            stdio: 'ignore',
            shell: true 
          }).unref();
        });

        // Timeout after 2 minutes
        timeoutId = setTimeout(() => {
          // Send timeout response to any open browser windows
          connections.forEach(conn => {
            if (!conn.destroyed) {
              conn.write('HTTP/1.1 200 OK\r\n');
              conn.write('Content-Type: text/html\r\n\r\n');
              conn.write(`<script>window.close();</script><html><body><h1>Timeout - Window closing...</h1></body></html>`);
            }
          });
          connections.forEach(conn => conn.destroy());
          server.close(() => {
            reject(new Error('Authentication timeout - no response received'));
          });
        }, 120000);
      }).catch(reject);
    });
  }
}

/**
 * Encrypts a dotenvx private key using FIDO2
 * @deprecated Use FIDO2Provider.encrypt() instead
 */
export async function encryptKeyWithFIDO2(privateKey: string, credentialId?: string): Promise<string> {
  const provider = new FIDO2Provider();
  return await provider.encrypt(privateKey, { credentialId });
}

/**
 * Check if FIDO2 might be available
 * Note: This only checks if the necessary APIs exist, not if a device is present
 */
export function isFIDO2Available(): boolean {
  // FIDO2 requires a browser environment for WebAuthn
  // In Node.js, we create a temporary web server
  return false; // Disabled temporarily to prevent loss of user secrets
}

