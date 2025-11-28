/**
 * Tests for simple encrypt, decrypt, set, and get operations
 */

import { expect } from 'chai';
import { describe, it, beforeEach, afterEach } from 'mocha';
import {
  createTestEnvironment,
  createEnvFile,
  createKeysFile,
  runVhsmCommand,
  runDotenvxCommand,
  fileExists,
  readFile,
} from './utils/test-helpers.js';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
// Note: Tests import from dist/ since we're testing the compiled code

describe('Simple Operations', () => {
  let env: ReturnType<typeof createTestEnvironment>;

  beforeEach(() => {
    env = createTestEnvironment('simple-ops');
  });

  afterEach(() => {
    env.cleanup();
  });

  describe('Encrypt', () => {
    it('should encrypt a .env.keys file with password provider', async () => {
      // Create .env file
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
        API_KEY: 'my-api-key',
      });

      // Create .env.keys file using dotenvx
      runDotenvxCommand(['encrypt'], env.testDir);

      // Verify .env.keys exists
      expect(fileExists(env.testDir, '.env.keys')).to.be.true;

      // Encrypt with vhsm
      const result = await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
      expect(fileExists(env.testDir, '.env.keys.encrypted')).to.be.true;
      expect(fileExists(env.testDir, '.env.keys')).to.be.false; // Should be deleted by default
    });

    it('should preserve .env.keys file when --no-delete is used', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const result = await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '--no-delete'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
      expect(fileExists(env.testDir, '.env.keys.encrypted')).to.be.true;
      expect(fileExists(env.testDir, '.env.keys')).to.be.true; // Should be preserved
    });
  });

  describe('Decrypt', () => {
    it('should decrypt and run dotenvx decrypt', async () => {
      // Setup: Create encrypted keys
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // Encrypt with vhsm
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      // Decrypt
      const result = await runVhsmCommand(
        ['decrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });

    it('should restore keys to .env.keys file with --restore', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['decrypt', '-p', 'password', '-pw', 'testpassword123', '--restore'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
      expect(fileExists(env.testDir, '.env.keys')).to.be.true;
    });
  });

  describe('Get', () => {
    it('should get a specific environment variable', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
        API_KEY: 'my-api-key',
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
      expect(result.stdout).to.include('my-secret-value');
    });

    it('should get all environment variables when no key specified', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
        API_KEY: 'my-api-key',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['get', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
      expect(result.stdout).to.include('SECRET_KEY');
      expect(result.stdout).to.include('API_KEY');
    });
  });

  describe('Set', () => {
    it('should set an environment variable', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['set', 'NEW_KEY', 'new-value', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);

      // Verify the key was added
      const envContent = readFile(env.testDir, '.env');
      expect(envContent).to.include('NEW_KEY');
    });

    it('should set a plain text value with --plain flag', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['set', 'PLAIN_KEY', 'plain-value', '-p', 'password', '-pw', 'testpassword123', '--plain'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Run', () => {
    it('should run a command with decrypted environment variables', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      // Create a test script
      const testScript = `
        if (process.env.SECRET_KEY === 'my-secret-value') {
          console.log('SUCCESS');
          process.exit(0);
        } else {
          console.log('FAILED');
          process.exit(1);
        }
      `;
      const scriptPath = join(env.testDir, 'test-script.js');
      writeFileSync(scriptPath, testScript);

      const result = await runVhsmCommand(
        ['run', '-pw', 'testpassword123', 'node', 'test-script.js'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
      expect(result.stdout).to.include('SUCCESS');
    });
  });
});

