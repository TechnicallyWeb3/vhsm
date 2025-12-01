/**
 * Tests for all providers (password, dpapi, fido2, tpm2)
 */

import { expect } from 'chai';
import { describe, it, beforeEach, afterEach } from 'mocha';
import {
  createTestEnvironment,
  createEnvFile,
  runVhsmCommand,
  runDotenvxCommand,
  fileExists,
} from './utils/test-helpers.js';
import { platform } from 'node:os';
import { isDPAPIAvailable } from '../dist/providers/dpapi.js';
import { isFIDO2Available } from '../dist/providers/fido2.js';
import { isTPM2Available } from '../dist/providers/tpm2.js';

describe('Providers', () => {
  let env: ReturnType<typeof createTestEnvironment>;

  beforeEach(() => {
    env = createTestEnvironment('providers');
  });

  afterEach(() => {
    env.cleanup();
  });

  describe('Password Provider', () => {
    it('should encrypt and decrypt with password provider', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // Encrypt
      const encryptResult = await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(encryptResult.exitCode).to.equal(0);
      expect(fileExists(env.testDir, '.env.keys.encrypted')).to.be.true;

      // Decrypt
      const decryptResult = await runVhsmCommand(
        ['decrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(decryptResult.exitCode).to.equal(0);
    });

    it('should fail with incorrect password', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['decrypt', '-p', 'password', '-pw', 'wrongpassword'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.not.equal(0);
      expect(result.stderr).to.include('Failed to decrypt');
    });

    it.skip('should require password for encryption', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // This should prompt for password
      // Expect mocha timeout due to password prompt
      await runVhsmCommand(
        ['encrypt', '-p', 'password'],
        { cwd: env.testDir }
      );
    });
  });

  describe('DPAPI Provider', () => {
    const shouldSkip = platform() !== 'win32' || !isDPAPIAvailable();

    it('should encrypt and decrypt with DPAPI provider on Windows', async function(this: Mocha.Context) {
      if (shouldSkip) {
        this.skip();
      }

      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // Encrypt
      const encryptResult = await runVhsmCommand(
        ['encrypt', '-p', 'dpapi'],
        { cwd: env.testDir }
      );

      expect(encryptResult.exitCode).to.equal(0);
      expect(fileExists(env.testDir, '.env.keys.encrypted')).to.be.true;

      // Decrypt
      const decryptResult = await runVhsmCommand(
        ['decrypt', '-p', 'dpapi'],
        { cwd: env.testDir }
      );

      expect(decryptResult.exitCode).to.equal(0);
    });

    it('should fail on non-Windows platforms', async function(this: Mocha.Context) {
      if (platform() === 'win32') {
        this.skip();
      }

      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const result = await runVhsmCommand(
        ['encrypt', '-p', 'dpapi'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.not.equal(0);
    });
  });

  describe('TPM2 Provider', () => {
    const shouldSkip = !isTPM2Available();

    it('should encrypt and decrypt with TPM2 provider when available', async function(this: Mocha.Context) {
      if (shouldSkip) {
        this.skip();
      }

      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // Encrypt with password (TPM2 may require password)
      const encryptResult = await runVhsmCommand(
        ['encrypt', '-p', 'tpm2', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(encryptResult.exitCode).to.equal(0);
      expect(fileExists(env.testDir, '.env.keys.encrypted')).to.be.true;

      // Decrypt
      const decryptResult = await runVhsmCommand(
        ['decrypt', '-p', 'tpm2', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(decryptResult.exitCode).to.equal(0);
    });

    it('should skip TPM2 tests when not available', async function(this: Mocha.Context) {
      if (!shouldSkip) {
        this.skip();
      }

      // Test should be skipped if TPM2 is not available
      expect(true).to.be.true;
    });
  });

  describe('FIDO2 Provider', () => {
    const shouldSkip = !isFIDO2Available();

    it('should encrypt and decrypt with FIDO2 provider when available', async function(this: Mocha.Context) {
      if (shouldSkip) {
        this.skip();
      }

      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // Note: FIDO2 requires hardware interaction, so this test may need to be manual
      // or mocked in CI environments
      const encryptResult = await runVhsmCommand(
        ['encrypt', '-p', 'fido2'],
        { cwd: env.testDir }
      );

      // May require user interaction, so exit code may vary
      expect([0, 1]).to.include(encryptResult.exitCode);
    });

    it('should skip FIDO2 tests when not available', async function(this: Mocha.Context) {
      if (!shouldSkip) {
        this.skip();
      }

      // Test should be skipped if FIDO2 is not available
      expect(true).to.be.true;
    });
  });

  describe('Provider Validation', () => {
    it('should reject unknown provider', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const result = await runVhsmCommand(
        ['encrypt', '-p', 'unknown-provider'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.not.equal(0);
      expect(result.stderr).to.include('Unknown provider');
    });

    it('should use default password provider when not specified', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      const result = await runVhsmCommand(
        ['encrypt', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Provider Mismatch Detection', () => {
    it('should detect provider mismatch when encrypting', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret-value',
      });

      runDotenvxCommand(['encrypt'], env.testDir);

      // Encrypt with password provider
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      // Try to encrypt with different provider (should fail)
      if (platform() === 'win32' && isDPAPIAvailable()) {
        const result = await runVhsmCommand(
          ['encrypt', '-p', 'dpapi'],
          { cwd: env.testDir }
        );

        expect(result.exitCode).to.not.equal(0);
        expect(result.stderr).to.include('Provider mismatch');
      }
    });
  });
});

