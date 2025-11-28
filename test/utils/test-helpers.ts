/**
 * Test utilities for vhsm CLI tests
 */

import { mkdirSync, writeFileSync, readFileSync, unlinkSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import { spawn } from 'node:child_process';

export interface TestEnvironment {
  testDir: string;
  cleanup: () => void;
}

/**
 * Create a temporary test directory with necessary files
 */
export function createTestEnvironment(testName: string): TestEnvironment {
  const testDir = join(process.cwd(), 'test-temp', testName);
  
  // Clean up if exists
  if (existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
  
  mkdirSync(testDir, { recursive: true });
  
  return {
    testDir,
    cleanup: () => {
      if (existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    }
  };
}

/**
 * Create a .env file for testing
 */
export function createEnvFile(testDir: string, content: Record<string, string>): string {
  const envPath = join(testDir, '.env');
  const envContent = Object.entries(content)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  writeFileSync(envPath, envContent);
  return envPath;
}

/**
 * Create a .env.keys file for testing
 */
export function createKeysFile(testDir: string, keys: Record<string, string>): string {
  const keysPath = join(testDir, '.env.keys');
  const header = `#/------------------!DOTENV_PRIVATE_KEYS!-------------------/
#/ private decryption keys. DO NOT commit to source control /
#/     [how it works](https://dotenvx.com/encryption)       /
#/----------------------------------------------------------/
`;
  const keysContent = Object.entries(keys)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  writeFileSync(keysPath, header + keysContent, { mode: 0o600 });
  return keysPath;
}

/**
 * Create an encrypted keys file for testing
 */
export function createEncryptedKeysFile(
  testDir: string,
  keys: Array<{ key: string; encryptedValue: string; provider: string }>
): string {
  const encryptedPath = join(testDir, '.env.keys.encrypted');
  const header = `#/-----------------!VHSM_PRIVATE_KEYS!------------------/
#/ VHSM encrypted keys. DO NOT commit to source control /
#/------------------------------------------------------/
`;
  const providerPrefix = (provider: string) => provider === 'password' ? 'encrypted' : provider;
  const keysContent = keys
    .map(({ key, encryptedValue, provider }) => `${key}=${providerPrefix(provider)}:${encryptedValue}`)
    .join('\n');
  writeFileSync(encryptedPath, header + keysContent, { mode: 0o600 });
  return encryptedPath;
}

/**
 * Read file content
 */
export function readFile(testDir: string, filename: string): string {
  return readFileSync(join(testDir, filename), 'utf-8');
}

/**
 * Check if file exists
 */
export function fileExists(testDir: string, filename: string): boolean {
  return existsSync(join(testDir, filename));
}

/**
 * Execute vhsm CLI command
 */
export async function runVhsmCommand(
  command: string[],
  options: {
    cwd?: string;
    env?: Record<string, string>;
    input?: string;
  } = {}
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const vhsmBin = join(process.cwd(), 'dist', 'cli', 'vhsm.js');
    const child = spawn(process.execPath, [vhsmBin, ...command], {
      cwd: options.cwd || process.cwd(),
      env: { ...process.env, ...options.env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    if (options.input && child.stdin) {
      child.stdin.write(options.input);
      child.stdin.end();
    }

    child.on('exit', (code) => {
      resolve({
        stdout,
        stderr,
        exitCode: code ?? 0,
      });
    });

    child.on('error', (error) => {
      resolve({
        stdout,
        stderr: stderr + error.message,
        exitCode: 1,
      });
    });
  });
}

/**
 * Run dotenvx command directly (for setup)
 */
export function runDotenvxCommand(args: string[], cwd: string): string {
  try {
    return execSync(`npx @dotenvx/dotenvx ${args.join(' ')}`, {
      cwd,
      encoding: 'utf-8',
      stdio: 'pipe',
    });
  } catch (error: any) {
    throw new Error(`dotenvx command failed: ${error.message}`);
  }
}

/**
 * Wait for a specified time (for cache expiration tests)
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

