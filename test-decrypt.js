import { readFileSync } from 'node:fs';
import { PasswordProvider } from './dist/providers/password.js';
import { createHash, createDecipheriv } from 'node:crypto';

const provider = new PasswordProvider();

// Read the encrypted key
const encrypted = readFileSync('test-encrypted.txt', 'utf-8').trim();
const parts = encrypted.split(':');
console.log('Encrypted key parts:', parts.length);

const [saltB64, ivB64, tagB64, encryptedB64] = parts;
const salt = Buffer.from(saltB64, 'base64');
const iv = Buffer.from(ivB64, 'base64');
const tag = Buffer.from(tagB64, 'base64');
const encryptedData = Buffer.from(encryptedB64, 'base64');

console.log('Salt length:', salt.length, 'expected: 16');
console.log('IV length:', iv.length, 'expected: 12');
console.log('Tag length:', tag.length, 'expected: 16');
console.log('Encrypted data length:', encryptedData.length);

// Derive key
const password = 'testpass123';
const key = createHash('sha256')
  .update(password)
  .update(salt)
  .digest();

console.log('Derived key length:', key.length, 'expected: 32');

// Try to decrypt manually
try {
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  
  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  
  console.log('✅ Manual decryption successful!');
  console.log('Decrypted content:', decrypted.toString('utf-8'));
} catch (error) {
  console.error('❌ Manual decryption failed:', error.message);
  console.error('Error code:', error.code);
}

// Try with provider
try {
  process.env.VHSM_DEBUG = '1';
  const decrypted = await provider.decrypt(encrypted, password);
  console.log('✅ Provider decryption successful!');
  console.log('Decrypted content:', decrypted);
} catch (error) {
  console.error('❌ Provider decryption failed:', error.message);
}
