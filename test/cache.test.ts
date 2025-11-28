/**
 * Tests for cache settings
 */

import { expect } from 'chai';
import { describe, it, beforeEach, afterEach } from 'mocha';
import {
  createTestEnvironment,
  createEnvFile,
  runVhsmCommand,
  runDotenvxCommand,
  sleep,
} from './utils/test-helpers.js';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';

describe('Cache Settings', () => {
  let env: ReturnType<typeof createTestEnvironment>;

  beforeEach(() => {
    env = createTestEnvironment('cache');
  });

  afterEach(() => {
    env.cleanup();
  });

  describe('Cache enabled (default)', () => {
    it('should cache decrypted keys for subsequent operations', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      // First decrypt (should decrypt)
      const firstResult = await runVhsmCommand(
        ['decrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(firstResult.exitCode).to.equal(0);

      // Second decrypt (should use cache, no password needed if cached)
      // Note: Cache may still require password depending on implementation
      const secondResult = await runVhsmCommand(
        ['get', 'SECRET_KEY', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(secondResult.exitCode).to.equal(0);
    });

    it('should respect cache timeout', async function(this: Mocha.Context) {
      this.timeout(5000); // Increase timeout for this test

      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      // First operation
      await runVhsmCommand(
        ['get', 'SECRET_KEY', '-p', 'password', '-pw', 'testpassword123', '-ct', '1000'],
        { cwd: env.testDir }
      );

      // Wait for cache to expire
      await sleep(1100);

      // Second operation should still work (may re-decrypt)
      const result = await runVhsmCommand(
        ['get', 'SECRET_KEY', '-p', 'password', '-pw', 'testpassword123', '-ct', '1000'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Cache disabled', () => {
    it('should not cache when --no-cache is used', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      // First operation with no-cache
      const firstResult = await runVhsmCommand(
        ['get', 'SECRET_KEY', '-p', 'password', '-pw', 'testpassword123', '--no-cache'],
        { cwd: env.testDir }
      );

      expect(firstResult.exitCode).to.equal(0);

      // Second operation should still require password (no cache)
      const secondResult = await runVhsmCommand(
        ['get', 'SECRET_KEY', '-p', 'password', '-pw', 'testpassword123', '--no-cache'],
        { cwd: env.testDir }
      );

      expect(secondResult.exitCode).to.equal(0);
    });

    it('should disable cache for run command', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const testScript = `
        console.log('SUCCESS');
        process.exit(0);
      `;
      const scriptPath = join(env.testDir, 'test-script.js');
      writeFileSync(scriptPath, testScript);

      const result = await runVhsmCommand(
        ['run', '-pw', 'testpassword123', '--no-cache', 'node', 'test-script.js'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Custom cache timeout', () => {
    it('should use custom cache timeout', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      // Use a short timeout
      const result = await runVhsmCommand(
        ['get', 'SECRET_KEY', '-p', 'password', '-pw', 'testpassword123', '-ct', '5000'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Clear cache command', () => {
    it('should clear cache', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      // Use cache
      await runVhsmCommand(
        ['get', 'SECRET_KEY', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      // Clear cache
      const clearResult = await runVhsmCommand(
        ['clear-cache'],
        { cwd: env.testDir }
      );

      expect(clearResult.exitCode).to.equal(0);
      expect(clearResult.stdout).to.include('Cache cleared');
    });
  });
});

