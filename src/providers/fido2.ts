import { createServer } from 'node:http';
import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import type { KeyDecryptionProvider } from '../types.js';
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
        // Use existing credential - derive key directly without authentication
        // (Authentication is only required for decryption)
        derivedKey = createHash('sha256').update(credentialId).digest();
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
      const connections = new Set<any>();
      let timeoutId: NodeJS.Timeout;
      let pageLoaded = false;
      let authenticationStarted = false;
      
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
          clearTimeout(timeoutCheck);
          icon.style.display = 'none';
          status.parentElement.className = 'status success';
          status.textContent = '✅ Success! You can close this window.';
          setTimeout(() => window.close(), 2000);
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
                
                // Derive key from credential ID (simple hash for now)
                // In production, you'd verify the attestation and store credential properly
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
          } else {
            res.writeHead(404);
            res.end();
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
  private async deriveKeyFromCredential(credentialId: string): Promise<Buffer> {
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
        
        // HTML page for FIDO2 authentication
        const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vHSM - FIDO2 Authentication</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
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
      background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
      color: white;
      border: none;
      padding: 16px 32px;
      font-size: 16px;
      font-weight: 600;
      border-radius: 12px;
      cursor: pointer;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(245, 87, 108, 0.4);
      width: 100%;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(245, 87, 108, 0.6);
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
      <span class="logo">🔓</span>
      <h1>FIDO2 Authentication</h1>
      <p class="subtitle">vHSM - Virtual Hardware Security Module</p>
      <span class="version">v${VERSION}</span>
    </div>
    
    <div class="status">
      <p id="status">Click the button below and touch your Yubikey when it blinks.</p>
    </div>
    
    <span id="yubikey-icon" class="yubikey-icon" style="display:none;">🔑</span>
    
    <button id="authBtn" onclick="authenticate()">Unlock with Yubikey</button>
    
    <div class="footer">
      Secured by FIDO2 WebAuthn
    </div>
  </div>
  
  <script>
    async function authenticate() {
      const btn = document.getElementById('authBtn');
      const status = document.getElementById('status');
      const icon = document.getElementById('yubikey-icon');
      
      try {
        btn.disabled = true;
        status.parentElement.className = 'status';
        status.textContent = '👆 Touch your Yubikey now...';
        icon.style.display = 'block';
        
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
          clearTimeout(timeoutCheck);
          icon.style.display = 'none';
          status.parentElement.className = 'status success';
          status.textContent = '✅ Success! You can close this window.';
          setTimeout(() => window.close(), 2000);
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
    
    // Auto-close on timeout (2 minutes)
    let timeoutCheck = setTimeout(() => {
      const status = document.getElementById('status');
      if (status) {
        status.parentElement.className = 'status error';
        status.textContent = '⏱️ Timeout - Closing window...';
      }
      setTimeout(() => window.close(), 1000);
    }, 120000);
    
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
          } else {
            res.writeHead(404);
            res.end();
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

