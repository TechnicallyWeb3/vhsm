/**
 * Tests for JSON file encryption and decryption
 */

import { expect } from 'chai';
import { describe, it, beforeEach, afterEach } from 'mocha';
import {
  createTestEnvironment,
  createEncryptedKeysFile,
  fileExists,
  readFile,
} from './utils/test-helpers.js';
import { encryptJsonFile, loadFile, getJsonValue } from '../dist/lib/files.js';
import { encryptKeyWithPassword } from '../dist/providers/password.js';
import { exec } from '../dist/exec.js';
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runVhsmCommand } from './utils/test-helpers.js';

describe('JSON File Encryption', () => {
  let env: ReturnType<typeof createTestEnvironment>;

  beforeEach(function() {
    // Use unique directory for each test to prevent cross-contamination
    // Include test name and timestamp to ensure uniqueness
    const testId = `${this.currentTest?.title || 'test'}-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    const safeTestId = testId.replace(/[^a-zA-Z0-9-_]/g, '_');
    env = createTestEnvironment(`json-encryption-${safeTestId}`);
  });

  afterEach(() => {
    env.cleanup();
  });

  describe('encryptJsonFile', () => {
    it('should encrypt a JSON file with password provider', async () => {
      // Create a test JSON file
      const testData = {
        user: {
          name: 'Test User',
          email: 'test@example.com',
        },
        apiKey: 'secret-api-key-123',
      };
      
      const jsonPath = join(env.testDir, 'config.json');
      writeFileSync(jsonPath, JSON.stringify(testData, null, 2));

      // Encrypt the JSON file
      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      // Verify encrypted file was created
      expect(fileExists(env.testDir, 'config.encrypted.json')).to.be.true;
      
      // Verify .env reference file was created
      expect(fileExists(env.testDir, '.env.config.json')).to.be.true;
      const envContent = readFile(env.testDir, '.env.config.json');
      expect(envContent).to.equal('CONFIG_JSON=config.encrypted.json');
      
      // Verify encrypted keys file was created
      expect(fileExists(env.testDir, '.env.keys.encrypted')).to.be.true;
      const encryptedKeysContent = readFile(env.testDir, '.env.keys.encrypted');
      expect(encryptedKeysContent).to.include('VHSM_PRIVATE_KEY_CONFIG_JSON=');
      
      // Verify encrypted JSON structure
      const encryptedJson = JSON.parse(readFile(env.testDir, 'config.encrypted.json'));
      expect(encryptedJson).to.have.property('encryptedBy', 'vhsm');
      expect(encryptedJson).to.have.property('version');
      expect(encryptedJson).to.have.property('encryptedValue');
      expect(encryptedJson.encryptedValue).to.match(/^encrypted:/);
      
      // Verify original file still exists (deleteOriginal: false)
      expect(fileExists(env.testDir, 'config.json')).to.be.true;
    });

    it('should delete original file when deleteOriginal is true', async () => {
      const testData = { key: 'value' };
      const jsonPath = join(env.testDir, 'test.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: true,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      expect(fileExists(env.testDir, 'test.json')).to.be.false;
      expect(fileExists(env.testDir, 'test.encrypted.json')).to.be.true;
    });

    it('should throw error for invalid JSON file', async () => {
      const jsonPath = join(env.testDir, 'invalid.json');
      writeFileSync(jsonPath, '{ invalid json }');

      try {
        await encryptJsonFile(jsonPath, {
          provider: 'password',
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
        });
        expect.fail('Should have thrown error for invalid JSON');
      } catch (error: any) {
        expect(error.message).to.include('Invalid JSON file');
      }
    });

    it('should throw error for non-existent file', async () => {
      const jsonPath = join(env.testDir, 'nonexistent.json');

      try {
        await encryptJsonFile(jsonPath, {
          provider: 'password',
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
        });
        expect.fail('Should have thrown error for non-existent file');
      } catch (error: any) {
        expect(error.message).to.include('JSON file not found');
      }
    });

    it('should handle nested JSON objects', async () => {
      const testData = {
        level1: {
          level2: {
            level3: {
              value: 'deep nested value',
            },
          },
        },
      };
      
      const jsonPath = join(env.testDir, 'nested.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      expect(fileExists(env.testDir, 'nested.encrypted.json')).to.be.true;
    });
  });

  describe('loadFile', () => {
    it('should decrypt and load an encrypted JSON file', async () => {
      // Create and encrypt a JSON file
      const testData = {
        user: 'Test User',
        age: 30,
        active: true,
      };
      
      const jsonPath = join(env.testDir, 'data.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      // Load the encrypted file
      const decryptedData = await loadFile(
        join(env.testDir, 'data.encrypted.json'),
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
        }
      );

      expect(decryptedData).to.deep.equal(testData);
    });

    it('should throw error for wrong password', async () => {
      const testData = { key: 'value' };
      const jsonPath = join(env.testDir, 'secret.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'correct-password',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      try {
        await loadFile(
          join(env.testDir, 'secret.encrypted.json'),
          {
            password: 'wrong-password',
            encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          }
        );
        expect.fail('Should have thrown error for wrong password');
      } catch (error: any) {
        expect(error.message).to.include('Failed to decrypt');
      }
    });

    it('should throw error for missing encrypted keys file', async () => {
      const testData = { key: 'value' };
      const jsonPath = join(env.testDir, 'test.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      try {
        await loadFile(
          join(env.testDir, 'test.encrypted.json'),
          {
            password: 'test-password-123',
            encryptedKeysFile: join(env.testDir, 'nonexistent.encrypted'),
          }
        );
        expect.fail('Should have thrown error for missing keys file');
      } catch (error: any) {
        expect(error.message).to.include('Encrypted keys file not found');
      }
    });

    it('should handle complex nested objects', async () => {
      const testData = {
        users: [
          { id: 1, name: 'User 1' },
          { id: 2, name: 'User 2' },
        ],
        settings: {
          theme: 'dark',
          notifications: {
            email: true,
            push: false,
          },
        },
        metadata: {
          version: '1.0.0',
          timestamp: '2024-01-01T00:00:00Z',
        },
      };
      
      const jsonPath = join(env.testDir, 'complex.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      const decryptedData = await loadFile(
        join(env.testDir, 'complex.encrypted.json'),
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
        }
      );

      expect(decryptedData).to.deep.equal(testData);
    });
  });

  describe('getJsonValue', () => {
    it('should get a top-level value using dot notation', async () => {
      const testData = {
        name: 'Test',
        version: '1.0.0',
      };
      
      const jsonPath = join(env.testDir, 'simple.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      const name = await getJsonValue(
        join(env.testDir, 'simple.encrypted.json'),
        'name',
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
        }
      );

      expect(name).to.equal('Test');
    });

    it('should get a nested value using dot notation', async () => {
      const testData = {
        user: {
          profile: {
            name: 'John Doe',
            age: 42,
          },
        },
      };
      
      const jsonPath = join(env.testDir, 'nested.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      const name = await getJsonValue(
        join(env.testDir, 'nested.encrypted.json'),
        'user.profile.name',
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
        }
      );

      expect(name).to.equal('John Doe');
    });

    it('should get a deeply nested value', async () => {
      const testData = {
        level1: {
          level2: {
            level3: {
              level4: {
                value: 'deep value',
              },
            },
          },
        },
      };
      
      const jsonPath = join(env.testDir, 'deep.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      const value = await getJsonValue(
        join(env.testDir, 'deep.encrypted.json'),
        'level1.level2.level3.level4.value',
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
        }
      );

      expect(value).to.equal('deep value');
    });

    it('should throw error for non-existent path', async () => {
      const testData = { user: { name: 'Test' } };
      const jsonPath = join(env.testDir, 'test.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      try {
        await getJsonValue(
          join(env.testDir, 'test.encrypted.json'),
          'user.nonexistent.path',
          {
            password: 'test-password-123',
            encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          }
        );
        expect.fail('Should have thrown error for non-existent path');
      } catch (error: any) {
        expect(error.message).to.include('not found in JSON file');
      }
    });

    it('should handle numeric values', async () => {
      const testData = {
        stats: {
          count: 42,
          percentage: 85.5,
        },
      };
      
      const jsonPath = join(env.testDir, 'numbers.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      const count = await getJsonValue(
        join(env.testDir, 'numbers.encrypted.json'),
        'stats.count',
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
        }
      );

      expect(count).to.equal(42);
    });

    it('should handle boolean values', async () => {
      const testData = {
        settings: {
          enabled: true,
          debug: false,
        },
      };
      
      const jsonPath = join(env.testDir, 'booleans.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      const enabled = await getJsonValue(
        join(env.testDir, 'booleans.encrypted.json'),
        'settings.enabled',
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
        }
      );

      expect(enabled).to.be.true;
    });
  });

  describe('exec() integration with JSON files', () => {
    let originalAllowExec: string | undefined;

    beforeEach(() => {
      // Save and set env var for exec tests
      originalAllowExec = process.env.VHSM_ALLOW_EXEC;
      process.env.VHSM_ALLOW_EXEC = 'true';
    });

    afterEach(() => {
      // Restore original value
      if (originalAllowExec !== undefined) {
        process.env.VHSM_ALLOW_EXEC = originalAllowExec;
      } else {
        delete process.env.VHSM_ALLOW_EXEC;
      }
    });

    it('should load entire JSON file using @vhsm syntax', async () => {
      const testData = {
        user: 'Test User',
        apiKey: 'secret-key',
      };
      
      const jsonPath = join(env.testDir, 'config.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      const result = await exec(
        async ({ config }) => {
          return config;
        },
        {
          config: '@vhsm CONFIG_JSON',
        },
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          // envFile is automatically inferred as .env.config.json from CONFIG_JSON
        }
      );

      expect(result).to.deep.equal(testData);
    });

    it('should load specific JSON value using @vhsm with dot notation', async () => {
      const testData = {
        database: {
          host: 'localhost',
          port: 5432,
          credentials: {
            username: 'admin',
            password: 'secret',
          },
        },
      };
      
      const jsonPath = join(env.testDir, 'db.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      const result = await exec(
        async ({ dbHost, dbUser, dbPass }) => {
          return { dbHost, dbUser, dbPass };
        },
        {
          dbHost: '@vhsm DB_JSON database.host',
          dbUser: '@vhsm DB_JSON database.credentials.username',
          dbPass: '@vhsm DB_JSON database.credentials.password',
        },
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          // envFile is automatically inferred as .env.db.json from DB_JSON
        }
      );

      expect(result).to.deep.equal({
        dbHost: 'localhost',
        dbUser: 'admin',
        dbPass: 'secret',
      });
    });

    it('should handle multiple JSON files in exec()', async () => {
      // Create first JSON file
      const config = { apiKey: 'key1', endpoint: 'https://api.example.com' };
      const configPath = join(env.testDir, 'config.json');
      writeFileSync(configPath, JSON.stringify(config));

      await encryptJsonFile(configPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      // Create second JSON file
      const secrets = { dbPassword: 'secret123', tokenSecret: 'token456' };
      const secretsPath = join(env.testDir, 'secrets.json');
      writeFileSync(secretsPath, JSON.stringify(secrets));

      await encryptJsonFile(secretsPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      const result = await exec(
        async ({ apiKey, dbPassword }) => {
          return { apiKey, dbPassword };
        },
        {
          apiKey: '@vhsm CONFIG_JSON apiKey',
          dbPassword: '@vhsm SECRETS_JSON dbPassword',
        },
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          // envFile is automatically inferred as .env.config.json from CONFIG_JSON (first key)
        }
      );

      expect(result).to.deep.equal({
        apiKey: 'key1',
        dbPassword: 'secret123',
      });
    });
  });

  describe('CLI decrypt command', () => {
    it('should decrypt JSON file using CLI command', async () => {
      const testData = {
        apiKey: 'secret-api-key-123',
        database: {
          host: 'localhost',
          port: 5432,
        },
      };
      
      const jsonPath = join(env.testDir, 'config.json');
      writeFileSync(jsonPath, JSON.stringify(testData, null, 2));

      // Encrypt using CLI
      const encryptResult = await runVhsmCommand(
        ['encrypt', 'config.json', '-p', 'password', '-pw', 'test-password-123', '--no-delete'],
        { cwd: env.testDir }
      );

      expect(encryptResult.exitCode).to.equal(0);
      expect(fileExists(env.testDir, 'config.encrypted.json')).to.be.true;

      // Decrypt using CLI
      const decryptResult = await runVhsmCommand(
        ['decrypt', 'config.encrypted.json', '-p', 'password', '-pw', 'test-password-123'],
        { cwd: env.testDir }
      );

      expect(decryptResult.exitCode).to.equal(0);
      
      // Verify decrypted file was created
      expect(fileExists(env.testDir, 'config.json')).to.be.true;
      
      // Verify content matches
      const decryptedContent = JSON.parse(readFile(env.testDir, 'config.json'));
      expect(decryptedContent).to.deep.equal(testData);
    });

    it('should decrypt JSON file with hyphens in filename', async () => {
      const testData = {
        user: {
          name: 'Test User',
          email: 'test@example.com',
        },
      };
      
      const jsonPath = join(env.testDir, 'test-config.json');
      writeFileSync(jsonPath, JSON.stringify(testData, null, 2));

      // Encrypt using CLI
      await runVhsmCommand(
        ['encrypt', 'test-config.json', '-p', 'password', '-pw', 'test-password-123', '--no-delete'],
        { cwd: env.testDir }
      );

      // Decrypt using CLI
      const decryptResult = await runVhsmCommand(
        ['decrypt', 'test-config.encrypted.json', '-p', 'password', '-pw', 'test-password-123'],
        { cwd: env.testDir }
      );

      expect(decryptResult.exitCode).to.equal(0);
      expect(fileExists(env.testDir, 'test-config.json')).to.be.true;
      
      const decryptedContent = JSON.parse(readFile(env.testDir, 'test-config.json'));
      expect(decryptedContent).to.deep.equal(testData);
    });

    it('should decrypt multiple JSON files', async () => {
      const configData = { apiKey: 'key123' };
      const secretsData = { dbPassword: 'secret456' };
      
      writeFileSync(join(env.testDir, 'config.json'), JSON.stringify(configData));
      writeFileSync(join(env.testDir, 'secrets.json'), JSON.stringify(secretsData));

      // Encrypt both files
      await runVhsmCommand(
        ['encrypt', 'config.json', 'secrets.json', '-p', 'password', '-pw', 'test-password-123', '--no-delete'],
        { cwd: env.testDir }
      );

      // Decrypt both files
      const decryptResult = await runVhsmCommand(
        ['decrypt', 'config.encrypted.json', 'secrets.encrypted.json', '-p', 'password', '-pw', 'test-password-123'],
        { cwd: env.testDir }
      );

      expect(decryptResult.exitCode).to.equal(0);
      
      const configContent = JSON.parse(readFile(env.testDir, 'config.json'));
      const secretsContent = JSON.parse(readFile(env.testDir, 'secrets.json'));
      
      expect(configContent).to.deep.equal(configData);
      expect(secretsContent).to.deep.equal(secretsData);
    });

    it('should decrypt to custom output path', async () => {
      const testData = { value: 'custom-output' };
      const jsonPath = join(env.testDir, 'input.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      // Encrypt
      await runVhsmCommand(
        ['encrypt', 'input.json', '-p', 'password', '-pw', 'test-password-123', '--no-delete'],
        { cwd: env.testDir }
      );

      // Decrypt to custom output
      const decryptResult = await runVhsmCommand(
        ['decrypt', 'input.encrypted.json', '-o', 'output.json', '-p', 'password', '-pw', 'test-password-123'],
        { cwd: env.testDir }
      );

      expect(decryptResult.exitCode).to.equal(0);
      expect(fileExists(env.testDir, 'output.json')).to.be.true;
      
      const outputContent = JSON.parse(readFile(env.testDir, 'output.json'));
      expect(outputContent).to.deep.equal(testData);
    });
  });

  describe('caching', () => {
    it('should cache decrypted JSON files', async () => {
      const testData = { value: 'cached' };
      const jsonPath = join(env.testDir, 'cachetest.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      // First load
      const start1 = Date.now();
      await loadFile(
        join(env.testDir, 'cachetest.encrypted.json'),
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          enableCache: true,
        }
      );
      const time1 = Date.now() - start1;

      // Second load (should be faster due to cache)
      const start2 = Date.now();
      await loadFile(
        join(env.testDir, 'cachetest.encrypted.json'),
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          enableCache: true,
        }
      );
      const time2 = Date.now() - start2;

      // Second load should be significantly faster (cached)
      expect(time2).to.be.lessThan(time1);
    });

    it('should not cache when enableCache is false', async () => {
      const testData = { value: 'no-cache' };
      const jsonPath = join(env.testDir, 'nocache.json');
      writeFileSync(jsonPath, JSON.stringify(testData));

      await encryptJsonFile(jsonPath, {
        provider: 'password',
        password: 'test-password-123',
        deleteOriginal: false,
        encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
      });

      // Load with cache disabled
      const data = await loadFile(
        join(env.testDir, 'nocache.encrypted.json'),
        {
          password: 'test-password-123',
          encryptedKeysFile: join(env.testDir, '.env.keys.encrypted'),
          enableCache: false,
        }
      );

      expect(data).to.deep.equal(testData);
    });
  });
});

