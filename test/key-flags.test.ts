/**
 * Tests for key and excluded-key flags
 */

import { expect } from 'chai';
import { describe, it, beforeEach, afterEach } from 'mocha';
import {
  createTestEnvironment,
  createEnvFile,
  runVhsmCommand,
  runDotenvxCommand,
  readFile,
} from './utils/test-helpers.js';

describe('Key and Excluded-Key Flags', () => {
  let env: ReturnType<typeof createTestEnvironment>;

  beforeEach(() => {
    env = createTestEnvironment('key-flags');
  });

  afterEach(() => {
    env.cleanup();
  });

  describe('Encrypt with -k flag', () => {
    it('should encrypt only specified keys', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'secret-value',
        API_KEY: 'api-value',
        TOKEN: 'token-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // Encrypt only SECRET_KEY and API_KEY
      const result = await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '-k', 'SECRET_KEY', 'API_KEY'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);

      // Verify encrypted file exists
      const encryptedContent = readFile(env.testDir, '.env.keys.encrypted');
      expect(encryptedContent).to.include('VHSM_PRIVATE_KEY');
    });

    it('should handle multiple keys with -k flag', async () => {
      createEnvFile(env.testDir, {
        KEY1: 'value1',
        KEY2: 'value2',
        KEY3: 'value3',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const result = await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '-k', 'KEY1', 'KEY2'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Encrypt with -ek flag', () => {
    it('should exclude specified keys from encryption', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'secret-value',
        API_KEY: 'api-value',
        PUBLIC_KEY: 'public-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // Encrypt all keys except PUBLIC_KEY
      const result = await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '-ek', 'PUBLIC_KEY'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });

    it('should handle multiple excluded keys', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'secret-value',
        API_KEY: 'api-value',
        PUBLIC_KEY: 'public-value',
        DEBUG: 'debug-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const result = await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '-ek', 'PUBLIC_KEY', 'DEBUG'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Decrypt with -k flag', () => {
    it('should decrypt only specified keys', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'secret-value',
        API_KEY: 'api-value',
        TOKEN: 'token-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['decrypt', '-p', 'password', '-pw', 'testpassword123', '-k', 'SECRET_KEY'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Decrypt with -ek flag', () => {
    it('should exclude specified keys from decryption', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'secret-value',
        API_KEY: 'api-value',
        PUBLIC_KEY: 'public-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['decrypt', '-p', 'password', '-pw', 'testpassword123', '-ek', 'PUBLIC_KEY'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Get with key filtering', () => {
    it('should get specific key', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'secret-value',
        API_KEY: 'api-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['get', 'SECRET_KEY', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
      expect(result.stdout).to.include('secret-value');
      expect(result.stdout).to.not.include('api-value');
    });
  });
});

