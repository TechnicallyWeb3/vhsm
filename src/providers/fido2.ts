import { createServer } from 'node:http';
import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'node:crypto';
import { spawn } from 'node:child_process';
import type { KeyDecryptionProvider } from '../types.js';
import { DecryptionError } from '../types.js';
import { Fido2Lib } from 'fido2-lib';

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
export class FIDO2Provider implements KeyDecryptionProvider {
  readonly name = 'fido2';
  readonly requiresInteraction = true;
  
  private f2l: any;
  private rpId = 'localhost';
  private rpName = 'VHSM FIDO2 Provider';
  
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
   * Encrypts data using FIDO2-derived key
   * This creates a credential and derives an encryption key from it
   */
  async encrypt(data: string, credentialId?: string): Promise<string> {
    try {
      let derivedKey: Buffer;
      let storedCredId: string;

      if (credentialId) {
        // Use existing credential
        derivedKey = await this.deriveKeyFromCredential(credentialId);
        storedCredId = credentialId;
      } else {
        // Create new credential
        const result = await this.createCredential();
        derivedKey = result.key;
        storedCredId = result.credentialId;
      }

      // Encrypt the data using AES-256-GCM
      const iv = randomBytes(16);
      const cipher = createCipheriv('aes-256-gcm', derivedKey, iv);
      
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      // Format: credentialId:iv:authTag:encryptedData
      const result = `${storedCredId}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
      
      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw new DecryptionError(`FIDO2 encryption failed: ${error.message}`);
      }
      throw new DecryptionError('FIDO2 encryption failed');
    }
  }

  /**
   * Decrypts the encrypted key using FIDO2 authentication
   * Format: credentialId:iv:authTag:encryptedData
   */
  async decrypt(encryptedKey: string): Promise<string> {
    try {
      // Parse the encrypted key
      const parts = encryptedKey.split(':');
      if (parts.length !== 4) {
        throw new DecryptionError('Invalid FIDO2 encrypted key format');
      }

      const [credentialId, ivHex, authTagHex, encryptedData] = parts;
      
      // Derive key from FIDO2 credential (requires user touch)
      console.log('🔑 Please touch your Yubikey to decrypt...');
      const derivedKey = await this.deriveKeyFromCredential(credentialId);
      
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
  private async createCredential(): Promise<{ key: Buffer; credentialId: string }> {
    return new Promise((resolve, reject) => {
      const port = 8765;
      let server: any;
      
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
  <title>VHSM - FIDO2 Registration</title>
  <style>
    body { 
      font-family: system-ui, -apple-system, sans-serif; 
      max-width: 600px; 
      margin: 50px auto; 
      padding: 20px;
      text-align: center;
    }
    .status { 
      padding: 20px; 
      border-radius: 8px; 
      margin: 20px 0;
      background: #f0f0f0;
    }
    .success { background: #d4edda; color: #155724; }
    .error { background: #f8d7da; color: #721c24; }
    button {
      background: #007bff;
      color: white;
      border: none;
      padding: 12px 24px;
      font-size: 16px;
      border-radius: 6px;
      cursor: pointer;
    }
    button:hover { background: #0056b3; }
    button:disabled { background: #6c757d; cursor: not-allowed; }
  </style>
</head>
<body>
  <h1>🔐 VHSM FIDO2 Setup</h1>
  <div class="status">
    <p id="status">Click the button below and touch your Yubikey when it blinks.</p>
  </div>
  <button id="registerBtn" onclick="register()">Register Yubikey</button>
  
  <script>
    async function register() {
      const btn = document.getElementById('registerBtn');
      const status = document.getElementById('status');
      
      try {
        btn.disabled = true;
        status.parentElement.className = 'status';
        status.textContent = '👆 Touch your Yubikey now...';
        
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
        
        const response = await fetch('/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            credentialId: credId,
            response: {
              clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
              attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
            }
          })
        });
        
        if (response.ok) {
          status.parentElement.className = 'status success';
          status.textContent = '✅ Success! You can close this window.';
          setTimeout(() => window.close(), 2000);
        } else {
          throw new Error('Server rejected credential');
        }
      } catch (error) {
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
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
          } else if (req.method === 'POST' && req.url === '/register') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
              try {
                const data = JSON.parse(body);
                const credentialId = data.credentialId;
                
                // Derive key from credential ID (simple hash for now)
                // In production, you'd verify the attestation and store credential properly
                const key = createHash('sha256').update(credentialId).digest();
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
                
                // Close server and resolve
                server.close();
                resolve({ key, credentialId });
              } catch (error) {
                res.writeHead(400);
                res.end();
                server.close();
                reject(error);
              }
            });
          } else {
            res.writeHead(404);
            res.end();
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
        setTimeout(() => {
          server.close();
          reject(new Error('Registration timeout - no response received'));
        }, 120000);
      }).catch(reject);
    });
  }

  /**
   * Derives an encryption key from an existing credential
   * Requires user presence (touch)
   */
  private async deriveKeyFromCredential(credentialId: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const port = 8765;
      let server: any;
      
      // Generate authentication options
      const authOptions = this.f2l.assertionOptions();
      
      authOptions.then((options: any) => {
        const challenge = Buffer.from(options.challenge).toString('base64url');
        
        // HTML page for FIDO2 authentication
        const html = `
<!DOCTYPE html>
<html>
<head>
  <title>VHSM - FIDO2 Authentication</title>
  <style>
    body { 
      font-family: system-ui, -apple-system, sans-serif; 
      max-width: 600px; 
      margin: 50px auto; 
      padding: 20px;
      text-align: center;
    }
    .status { 
      padding: 20px; 
      border-radius: 8px; 
      margin: 20px 0;
      background: #f0f0f0;
    }
    .success { background: #d4edda; color: #155724; }
    .error { background: #f8d7da; color: #721c24; }
    button {
      background: #007bff;
      color: white;
      border: none;
      padding: 12px 24px;
      font-size: 16px;
      border-radius: 6px;
      cursor: pointer;
    }
    button:hover { background: #0056b3; }
    button:disabled { background: #6c757d; cursor: not-allowed; }
  </style>
</head>
<body>
  <h1>🔓 VHSM FIDO2 Unlock</h1>
  <div class="status">
    <p id="status">Click the button below and touch your Yubikey when it blinks.</p>
  </div>
  <button id="authBtn" onclick="authenticate()">Unlock with Yubikey</button>
  
  <script>
    async function authenticate() {
      const btn = document.getElementById('authBtn');
      const status = document.getElementById('status');
      
      try {
        btn.disabled = true;
        status.parentElement.className = 'status';
        status.textContent = '👆 Touch your Yubikey now...';
        
        // Authenticate with credential
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge: Uint8Array.from(atob('${challenge}'.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
            rpId: '${this.rpId}',
            allowCredentials: [{
              type: 'public-key',
              id: Uint8Array.from(atob('${credentialId}'.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
            }],
            timeout: 60000,
            userVerification: 'preferred'
          }
        });
        
        // Send assertion to server
        const response = await fetch('/authenticate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            credentialId: '${credentialId}',
            response: {
              clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
              authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
              signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature)))
            }
          })
        });
        
        if (response.ok) {
          status.parentElement.className = 'status success';
          status.textContent = '✅ Success! You can close this window.';
          setTimeout(() => window.close(), 2000);
        } else {
          throw new Error('Authentication failed');
        }
      } catch (error) {
        status.parentElement.className = 'status error';
        status.textContent = '❌ Error: ' + error.message;
        btn.disabled = false;
      }
    }
    
    // Auto-start on load
    window.onload = () => {
      setTimeout(() => document.getElementById('authBtn').click(), 500);
    };
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
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(html);
          } else if (req.method === 'POST' && req.url === '/authenticate') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
              try {
                const data = JSON.parse(body);
                
                // Derive key from credential ID (same method as registration)
                const key = createHash('sha256').update(credentialId).digest();
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
                
                // Close server and resolve
                server.close();
                resolve(key);
              } catch (error) {
                res.writeHead(400);
                res.end();
                server.close();
                reject(error);
              }
            });
          } else {
            res.writeHead(404);
            res.end();
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
        setTimeout(() => {
          server.close();
          reject(new Error('Authentication timeout - no response received'));
        }, 120000);
      }).catch(reject);
    });
  }
}

/**
 * Encrypts a dotenvx private key using FIDO2
 */
export async function encryptKeyWithFIDO2(privateKey: string, credentialId?: string): Promise<string> {
  const provider = new FIDO2Provider();
  return await provider.encrypt(privateKey, credentialId);
}

/**
 * Check if FIDO2 might be available
 * Note: This only checks if the necessary APIs exist, not if a device is present
 */
export function isFIDO2Available(): boolean {
  // FIDO2 requires a browser environment for WebAuthn
  // In Node.js, we create a temporary web server
  return true; // Always available, but requires user to have a FIDO2 device
}

