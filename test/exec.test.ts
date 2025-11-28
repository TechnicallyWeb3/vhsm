/**
 * Tests for exec function and allowExec blockers
 */

import { expect } from 'chai';
import { describe, it, beforeEach, afterEach } from 'mocha';
import {
  createTestEnvironment,
  createEnvFile,
  createEncryptedKeysFile,
  runDotenvxCommand,
} from './utils/test-helpers.js';
import { exec } from '../dist/exec.js';
import { encryptKeyWithPassword } from '../dist/providers/password.js';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

describe('Exec Function', () => {
  let env: ReturnType<typeof createTestEnvironment>;

  beforeEach(() => {
    env = createTestEnvironment('exec');
  });

  afterEach(() => {
    env.cleanup();
  });

  describe('allowExec blocker', () => {
    it('should throw error when allowExec is not enabled', async () => {
      createEnvFile(env.testDir, {
        API_KEY: 'test-api-key',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // Read the .env.keys file to get the private key
      const keysContent = readFileSync(join(env.testDir, '.env.keys'), 'utf-8');
      const keyMatch = /DOTENV_PRIVATE_KEY=(.+)/.exec(keysContent);
      if (!keyMatch) {
        throw new Error('Could not find DOTENV_PRIVATE_KEY');
      }
      const privateKey = keyMatch[1];

      // Encrypt the key
      const encryptedKey = await encryptKeyWithPassword(privateKey, 'testpassword123');
      createEncryptedKeysFile(env.testDir, [
        {
          key: 'VHSM_PRIVATE_KEY',
          encryptedValue: encryptedKey,
          provider: 'password',
        },
      ]);

      // Try to use exec without allowExec enabled
      try {
        await exec(
          async ({ apiKey }) => {
            return apiKey;
          },
          {
            apiKey: '@vhsm API_KEY',
          },
          {
            encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
            envFile: join(env.testDir, '.env'),
            password: 'testpassword123',
            allowExec: false,
          }
        );
        expect.fail('Should have thrown an error');
      } catch (error: any) {
        expect(error.message).to.include('vhsm.exec() is disabled by default for security');
      }
    });

    it('should work when allowExec is enabled in options', async () => {
      createEnvFile(env.testDir, {
        API_KEY: 'test-api-key',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const keysContent = readFileSync(join(env.testDir, '.env.keys'), 'utf-8');
      const keyMatch = /DOTENV_PRIVATE_KEY=(.+)/.exec(keysContent);
      if (!keyMatch) {
        throw new Error('Could not find DOTENV_PRIVATE_KEY');
      }
      const privateKey = keyMatch[1];

      const encryptedKey = await encryptKeyWithPassword(privateKey, 'testpassword123');
      createEncryptedKeysFile(env.testDir, [
        {
          key: 'VHSM_PRIVATE_KEY',
          encryptedValue: encryptedKey,
          provider: 'password',
        },
      ]);

      const result = await exec(
        async ({ apiKey }) => {
          return apiKey;
        },
        {
          apiKey: '@vhsm API_KEY',
        },
        {
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          envFile: join(env.testDir, '.env'),
          password: 'testpassword123',
          allowExec: true,
        }
      );

      expect(result).to.equal('test-api-key');
    });

    it('should work when allowExec is enabled via environment variable', async () => {
      createEnvFile(env.testDir, {
        API_KEY: 'test-api-key',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const keysContent = readFileSync(join(env.testDir, '.env.keys'), 'utf-8');
      const keyMatch = /DOTENV_PRIVATE_KEY=(.+)/.exec(keysContent);
      if (!keyMatch) {
        throw new Error('Could not find DOTENV_PRIVATE_KEY');
      }
      const privateKey = keyMatch[1];

      const encryptedKey = await encryptKeyWithPassword(privateKey, 'testpassword123');
      createEncryptedKeysFile(env.testDir, [
        {
          key: 'VHSM_PRIVATE_KEY',
          encryptedValue: encryptedKey,
          provider: 'password',
        },
      ]);

      // Set environment variable
      const originalEnv = process.env.VHSM_ALLOW_EXEC;
      process.env.VHSM_ALLOW_EXEC = 'true';

      try {
        const result = await exec(
          async ({ apiKey }) => {
            return apiKey;
          },
          {
            apiKey: '@vhsm API_KEY',
          },
          {
            encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
            envFile: join(env.testDir, '.env'),
            password: 'testpassword123',
          }
        );

        expect(result).to.equal('test-api-key');
      } finally {
        // Restore original environment
        if (originalEnv !== undefined) {
          process.env.VHSM_ALLOW_EXEC = originalEnv;
        } else {
          delete process.env.VHSM_ALLOW_EXEC;
        }
      }
    });
  });

  describe('Exec functionality', () => {
    it('should inject environment variables with @vhsm prefix', async () => {
      createEnvFile(env.testDir, {
        API_KEY: 'test-api-key',
        SECRET_KEY: 'test-secret-key',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const keysContent = readFileSync(join(env.testDir, '.env.keys'), 'utf-8');
      const keyMatch = /DOTENV_PRIVATE_KEY=(.+)/.exec(keysContent);
      if (!keyMatch) {
        throw new Error('Could not find DOTENV_PRIVATE_KEY');
      }
      const privateKey = keyMatch[1];

      const encryptedKey = await encryptKeyWithPassword(privateKey, 'testpassword123');
      createEncryptedKeysFile(env.testDir, [
        {
          key: 'VHSM_PRIVATE_KEY',
          encryptedValue: encryptedKey,
          provider: 'password',
        },
      ]);

      const result = await exec(
        async ({ apiKey, secretKey, regularValue }) => {
          return {
            apiKey,
            secretKey,
            regularValue,
          };
        },
        {
          apiKey: '@vhsm API_KEY',
          secretKey: '@vhsm SECRET_KEY',
          regularValue: 'not-from-env',
        },
        {
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          envFile: join(env.testDir, '.env'),
          password: 'testpassword123',
          allowExec: true,
        }
      );

      expect(result.apiKey).to.equal('test-api-key');
      expect(result.secretKey).to.equal('test-secret-key');
      expect(result.regularValue).to.equal('not-from-env');
    });

    it('should throw error when environment variable is not found', async () => {
      createEnvFile(env.testDir, {
        API_KEY: 'test-api-key',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const keysContent = readFileSync(join(env.testDir, '.env.keys'), 'utf-8');
      const keyMatch = /DOTENV_PRIVATE_KEY=(.+)/.exec(keysContent);
      if (!keyMatch) {
        throw new Error('Could not find DOTENV_PRIVATE_KEY');
      }
      const privateKey = keyMatch[1];

      const encryptedKey = await encryptKeyWithPassword(privateKey, 'testpassword123');
      createEncryptedKeysFile(env.testDir, [
        {
          key: 'VHSM_PRIVATE_KEY',
          encryptedValue: encryptedKey,
          provider: 'password',
        },
      ]);

      try {
        await exec(
          async ({ missingKey }) => {
            return missingKey;
          },
          {
            missingKey: '@vhsm NONEXISTENT_KEY',
          },
          {
            encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
            envFile: join(env.testDir, '.env'),
            password: 'testpassword123',
            allowExec: true,
          }
        );
        expect.fail('Should have thrown an error');
      } catch (error: any) {
        expect(error.message).to.include('not found');
      }
    });

    it('should support nested exec calls with Promise values', async () => {
      createEnvFile(env.testDir, {
        API_KEY: 'test-api-key',
        SECRET_KEY: 'test-secret-key',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const keysContent = readFileSync(join(env.testDir, '.env.keys'), 'utf-8');
      const keyMatch = /DOTENV_PRIVATE_KEY=(.+)/.exec(keysContent);
      if (!keyMatch) {
        throw new Error('Could not find DOTENV_PRIVATE_KEY');
      }
      const privateKey = keyMatch[1];

      const encryptedKey = await encryptKeyWithPassword(privateKey, 'testpassword123');
      createEncryptedKeysFile(env.testDir, [
        {
          key: 'VHSM_PRIVATE_KEY',
          encryptedValue: encryptedKey,
          provider: 'password',
        },
      ]);

      // First exec call
      const firstResult = await exec(
        async ({ apiKey }) => {
          return apiKey;
        },
        {
          apiKey: '@vhsm API_KEY',
        },
        {
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          envFile: join(env.testDir, '.env'),
          password: 'testpassword123',
          allowExec: true,
        }
      );

      // Second exec call using result from first as Promise
      const secondResult = await exec(
        async ({ apiKey, secretKey }) => {
          return {
            apiKey: await apiKey,
            secretKey,
          };
        },
        {
          apiKey: Promise.resolve(firstResult),
          secretKey: '@vhsm SECRET_KEY',
        },
        {
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          envFile: join(env.testDir, '.env'),
          password: 'testpassword123',
          allowExec: true,
        }
      );

      expect(secondResult.apiKey).to.equal('test-api-key');
      expect(secondResult.secretKey).to.equal('test-secret-key');
    });

    it('should handle errors and clear sensitive data', async () => {
      createEnvFile(env.testDir, {
        API_KEY: 'test-api-key',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const keysContent = readFileSync(join(env.testDir, '.env.keys'), 'utf-8');
      const keyMatch = /DOTENV_PRIVATE_KEY=(.+)/.exec(keysContent);
      if (!keyMatch) {
        throw new Error('Could not find DOTENV_PRIVATE_KEY');
      }
      const privateKey = keyMatch[1];

      const encryptedKey = await encryptKeyWithPassword(privateKey, 'testpassword123');
      createEncryptedKeysFile(env.testDir, [
        {
          key: 'VHSM_PRIVATE_KEY',
          encryptedValue: encryptedKey,
          provider: 'password',
        },
      ]);

      try {
        await exec(
          async ({ apiKey }) => {
            throw new Error('Test error');
          },
          {
            apiKey: '@vhsm API_KEY',
          },
          {
            encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
            envFile: join(env.testDir, '.env'),
            password: 'testpassword123',
            allowExec: true,
          }
        );
        expect.fail('Should have thrown an error');
      } catch (error: any) {
        expect(error.message).to.include('Test error');
        // Sensitive data should be cleared even on error
      }
    });
  });
});

