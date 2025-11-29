/**
 * Tests for complex multi-file commands
 */

import { expect } from 'chai';
import { describe, it, beforeEach, afterEach } from 'mocha';
import {
  createTestEnvironment,
  createEnvFile,
  runVhsmCommand,
  runDotenvxCommand,
  fileExists,
  readFile,
} from './utils/test-helpers.js';
import { join } from 'node:path';
import { writeFileSync, existsSync, renameSync } from 'node:fs';

describe('Multi-File Operations', () => {
  let env: ReturnType<typeof createTestEnvironment>;

  beforeEach(() => {
    env = createTestEnvironment('multi-file');
  });

  afterEach(() => {
    env.cleanup();
  });

  describe('Multiple .env files', () => {
    it('should encrypt multiple .env files', async () => {
      // Create multiple .env files
      createEnvFile(env.testDir, {
        SECRET_KEY: 'production-secret',
      });
      const localPath = join(env.testDir, '.env.local');
      writeFileSync(localPath, 'API_KEY=local-api-key\n');

      // Encrypt both files
      runDotenvxCommand(['encrypt', '-f', '.env', '.env.local'], env.testDir);

      // Encrypt with vhsm
      const result = await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '-f', '.env', '.env.local'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
      expect(fileExists(env.testDir, '.env.keys.encrypted')).to.be.true;

      // Verify encrypted file contains keys for both files
      const encryptedContent = readFile(env.testDir, '.env.keys.encrypted');
      expect(encryptedContent).to.include('VHSM_PRIVATE_KEY');
      expect(encryptedContent).to.include('VHSM_PRIVATE_KEY_LOCAL');
    });

    it('should decrypt multiple .env files', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'production-secret',
      });
      const localPath = join(env.testDir, '.env.local');
      writeFileSync(localPath, 'API_KEY=local-api-key\n');

      runDotenvxCommand(['encrypt', '-f', '.env', '.env.local'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '-f', '.env', '.env.local'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['decrypt', '-p', 'password', '-pw', 'testpassword123', '-f', '.env', '.env.local'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });

    it('should get values from multiple .env files', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'production-secret',
      });
      const localPath = join(env.testDir, '.env.local');
      writeFileSync(localPath, 'API_KEY=local-api-key\n');

      runDotenvxCommand(['encrypt', '-f', '.env', '.env.local'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '-f', '.env', '.env.local'],
        { cwd: env.testDir }
      );

      const result = await runVhsmCommand(
        ['get', '-pw', 'testpassword123', '-f', '.env', '.env.local'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
      expect(result.stdout).to.include('SECRET_KEY');
      expect(result.stdout).to.include('API_KEY');
    });

    it('should run command with multiple .env files', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'production-secret',
      });
      const localPath = join(env.testDir, '.env.local');
      writeFileSync(localPath, 'API_KEY=local-api-key\n');

      runDotenvxCommand(['encrypt', '-f', '.env', '.env.local'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '-f', '.env', '.env.local'],
        { cwd: env.testDir }
      );

      const testScript = `
        if (process.env.SECRET_KEY === 'production-secret' && process.env.API_KEY === 'local-api-key') {
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
        ['run', '-pw', 'testpassword123', '-f', '.env', '-f', '.env.local', '--', 'node', 'test-script.js'],
        { cwd: env.testDir }
      );

      if (result.exitCode !== 0) {
        console.log('STDERR:', result.stderr);
        console.log('STDOUT:', result.stdout);
      }
      expect(result.exitCode).to.equal(0);
      expect(result.stdout).to.include('SUCCESS');
    });
  });

  describe('Custom encrypted keys file path', () => {
    it('should work with custom encrypted keys file path', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'my-secret',
      });

      // First create .env.keys with dotenvx, then rename it to custom.keys
      runDotenvxCommand(['encrypt'], env.testDir);
      const { renameSync } = await import('node:fs');
      const originalKeys = join(env.testDir, '.env.keys');
      const customKeys = join(env.testDir, 'custom.keys');
      if (existsSync(originalKeys)) {
        renameSync(originalKeys, customKeys);
      }
      
      // Use -fk to specify custom keys file, output will be custom.keys.encrypted
      const encryptResult = await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123', '-fk', 'custom.keys'],
        { cwd: env.testDir }
      );

      if (encryptResult.exitCode !== 0) {
        console.log('Encrypt STDERR:', encryptResult.stderr);
        console.log('Encrypt STDOUT:', encryptResult.stdout);
      }

      expect(encryptResult.exitCode).to.equal(0);
      expect(fileExists(env.testDir, 'custom.keys.encrypted')).to.be.true;

      const result = await runVhsmCommand(
        ['decrypt', '-p', 'password', '-pw', 'testpassword123', '-ef', 'custom.keys.encrypted'],
        { cwd: env.testDir }
      );

      expect(result.exitCode).to.equal(0);
    });
  });

  describe('Environment variable injection', () => {
    it('should inject environment variables with -e flag', async () => {
      createEnvFile(env.testDir, {
        SECRET_KEY: 'file-secret',
      });

      runDotenvxCommand(['encrypt'], env.testDir);
      await runVhsmCommand(
        ['encrypt', '-p', 'password', '-pw', 'testpassword123'],
        { cwd: env.testDir }
      );

      const testScript = `
        if (process.env.INJECTED_KEY === 'injected-value') {
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
        ['run', '-pw', 'testpassword123', '-e', 'INJECTED_KEY=injected-value', '--', 'node', 'test-script.js'],
        { cwd: env.testDir }
      );

      if (result.exitCode !== 0) {
        console.log('STDERR:', result.stderr);
        console.log('STDOUT:', result.stdout);
      }
      expect(result.exitCode).to.equal(0);
      expect(result.stdout).to.include('SUCCESS');
    });
  });
});

