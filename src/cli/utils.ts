import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join, basename } from 'node:path';
import { readFileSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { listProviders } from '../providers/index.js';

const require = createRequire(import.meta.url);
const resolvedDotenvxBin = resolveDotenvxBin();
let warnedAboutGlobalDotenvx = false;

function resolveDotenvxBin(): string | null {
  try {
    const pkgPath = require.resolve('@dotenvx/dotenvx/package.json');
    const pkgDir = dirname(pkgPath);
    const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    const binField =
      typeof pkgJson.bin === 'string'
        ? pkgJson.bin
        : pkgJson.bin?.dotenvx;
    if (binField) {
      return join(pkgDir, binField);
    }
  } catch (error) {
    // ignore - fallback will use global command
  }
  return null;
}

export function spawnDotenvx(args: string[], options: Parameters<typeof spawn>[2]) {
  if (resolvedDotenvxBin) {
    return spawn(process.execPath, [resolvedDotenvxBin, ...args], {
      ...options,
      shell: false,
    });
  }

  if (!warnedAboutGlobalDotenvx) {
    console.warn('⚠️  Local @dotenvx/dotenvx not found. Falling back to global "dotenvx" command.');
    warnedAboutGlobalDotenvx = true;
  }

  return spawn('dotenvx', args, options);
}

/**
 * Load and validate encrypted key file
 */
export function loadEncryptedKeyFile(keyPath: string): string {
  try {
    const content = readFileSync(keyPath, 'utf-8').trim();
    if (!content) {
      throw new Error('Encrypted key file is empty');
    }
    return content;
  } catch (error) {
    throw new Error(`Failed to read encrypted key file: ${keyPath}. ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Parse all VHSM_PRIVATE_KEY* entries from encrypted file
 * Supports "encrypted:" (password), "dpapi:", "fido2:", and "tpm2:" prefixes
 */
export function parseEncryptedKeys(content: string): Array<{ vhsmKey: string; encryptedValue: string; provider: string }> {
  const keys: Array<{ vhsmKey: string; encryptedValue: string; provider: string }> = [];
  const lines = content.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#') || !trimmed) {
      continue;
    }

    // Match VHSM_PRIVATE_KEY[_SUFFIX]=provider:encryptedValue
    // The provider must be one of the known providers, followed by a colon
    // The encrypted value may contain colons, so we need to match only the provider name
    const providers = listProviders();
    const providerPattern = providers.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    const match = new RegExp(`^(VHSM_PRIVATE_KEY[^=]*)=(${providerPattern}):(.+)$`).exec(trimmed);
    if (match) {
      const provider = match[2];
      if (!listProviders().includes(provider)) {
        throw new Error(`Unknown provider: ${provider}. Available providers: ${listProviders().join(', ')}`);
      }
      keys.push({
        vhsmKey: match[1],
        provider,
        encryptedValue: match[3],
      });
    }
  }
  
  return keys;
}

/**
 * Extract suffix from env file name
 * .env → ''
 * .env.local → '_LOCAL'
 * .env.production → '_PRODUCTION'
 * .env.config.json → '_CONFIG_JSON'
 * .env.local.v1 → '_LOCAL_V1'
 * ./backend/.env → '' (extracts filename first)
 * ./backend/.env.local → '_LOCAL' (extracts filename first)
 */
export function getEnvSuffix(envFile: string): string {
  // Extract just the filename from the path (e.g., ./backend/.env → .env)
  const filename = basename(envFile);
  
  if (filename === '.env') {
    return '';
  }
  
  // Split by '.' to get parts: ['.env', 'local'] or ['.env', 'config', 'json']
  const parts = filename.split('.');
  if (parts.length > 2) {
    // parts[0] is empty string, parts[1] is 'env', parts[2+] are the suffix parts
    // Join all parts after 'env' with underscores and convert to uppercase
    const suffixParts = parts.slice(2); // Skip empty string and 'env'
    return '_' + suffixParts.join('_').toUpperCase();
  }
  
  return '';
}

/**
 * Convert VHSM key name to DOTENV key name
 * VHSM_PRIVATE_KEY → DOTENV_PRIVATE_KEY
 * VHSM_PRIVATE_KEY_LOCAL → DOTENV_PRIVATE_KEY_LOCAL
 */
export function vhsmKeyToDotenvKey(vhsmKey: string): string {
  return vhsmKey.replace('VHSM_', 'DOTENV_');
}

/**
 * Match keys to env files based on suffixes
 */
export function matchKeysToEnvFiles(
  envFiles: string[],
  availableKeys: Array<{ vhsmKey: string; encryptedValue: string; provider: string }>
): Array<{ vhsmKey: string; dotenvKey: string; encryptedValue: string; provider: string; envFile: string }> {
  const keysToProcess: Array<{ vhsmKey: string; dotenvKey: string; encryptedValue: string; provider: string; envFile: string }> = [];
  
  for (const envFile of envFiles) {
    const suffix = getEnvSuffix(envFile);
    const vhsmKey = `VHSM_PRIVATE_KEY${suffix}`;
    const dotenvKey = `DOTENV_PRIVATE_KEY${suffix}`;
    
    // Find the matching encrypted key
    const keyEntry = availableKeys.find(k => k.vhsmKey === vhsmKey);
    if (keyEntry) {
      keysToProcess.push({
        vhsmKey,
        dotenvKey,
        encryptedValue: keyEntry.encryptedValue,
        provider: keyEntry.provider,
        envFile,
      });
    } else {
      console.warn(`⚠️  No encrypted key found for ${envFile} (looking for ${vhsmKey})`);
    }
  }
  
  return keysToProcess;
}

/**
 * Parse DOTENV_PRIVATE_KEY entries from .env.keys file
 */
export function parseDotenvKeys(content: string): Array<{ dotenvKey: string; envFile: string | null }> {
  const keys: Array<{ dotenvKey: string; envFile: string | null }> = [];
  const lines = content.split('\n');
  let currentEnvFile: string | null = null;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Track commented filename (e.g., "# .env.local")
    if (trimmed.startsWith('#') && !trimmed.startsWith('#/') && trimmed.length > 1) {
      const envFileMatch = /^#\s*(\.env[^\s]*)/.exec(trimmed);
      if (envFileMatch) {
        currentEnvFile = envFileMatch[1];
      }
      continue;
    }
    
    // Match DOTENV_PRIVATE_KEY[_SUFFIX]=...
    const match = /^(DOTENV_PRIVATE_KEY[^=]*)=(.*)/.exec(trimmed);
    if (match) {
      keys.push({
        dotenvKey: match[1],
        envFile: currentEnvFile,
      });
    }
  }
  
  return keys;
}

/**
 * Remove keys from .env.keys file
 */
export function removeKeysFromDotenvKeysFile(
  filePath: string,
  keysToRemove: string[]
): { removed: boolean; shouldDelete: boolean } {
  if (!existsSync(filePath)) {
    return { removed: false, shouldDelete: false };
  }
  
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const keysToRemoveSet = new Set(keysToRemove);
  
  const headerLines: string[] = [];
  const remainingLines: string[] = [];
  let removedAny = false;
  let pendingComment: string | null = null;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Keep header lines (starting with #/)
    if (trimmed.startsWith('#/')) {
      headerLines.push(line);
      pendingComment = null;
      continue;
    }
    
    // Track commented filename (e.g., "# .env.local")
    if (trimmed.startsWith('#') && !trimmed.startsWith('#/') && trimmed.length > 1) {
      const envFileMatch = /^#\s*(\.env[^\s]*)/.exec(trimmed);
      if (envFileMatch) {
        // Store this comment, but don't add it yet - wait to see if next line is a key to remove
        pendingComment = line;
        continue;
      }
    }
    
    // Check if this is a key line to remove
    const keyMatch = /^(DOTENV_PRIVATE_KEY[^=]*)=/.exec(trimmed);
    if (keyMatch && keysToRemoveSet.has(keyMatch[1])) {
      removedAny = true;
      // Skip this key and discard any pending comment
      pendingComment = null;
      continue;
    }
    
    // Keep this line - add pending comment first if it exists
    if (pendingComment !== null) {
      remainingLines.push(pendingComment);
      pendingComment = null;
    }
    remainingLines.push(line);
  }
  
  // Check if there are any keys remaining
  const remainingKeys = parseDotenvKeys(remainingLines.join('\n'));
  const shouldDelete = remainingKeys.length === 0;
  
  if (removedAny) {
    if (shouldDelete) {
      unlinkSync(filePath);
    } else {
      // Reconstruct file with header if it existed
      const newContent = headerLines.length > 0 
        ? headerLines.join('\n') + '\n' + remainingLines.join('\n')
        : remainingLines.join('\n');
      writeFileSync(filePath, newContent, { mode: 0o600 });
    }
  }
  
  return { removed: removedAny, shouldDelete };
}

/**
 * Remove keys from .env.keys.encrypted file
 */
export function removeKeysFromEncryptedFile(
  filePath: string,
  vhsmKeysToRemove: string[]
): { removed: boolean; shouldDelete: boolean } {
  if (!existsSync(filePath)) {
    return { removed: false, shouldDelete: false };
  }
  
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const keysToRemoveSet = new Set(vhsmKeysToRemove);
  
  const headerLines: string[] = [];
  const remainingLines: string[] = [];
  let removedAny = false;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Keep header lines (starting with #/)
    if (trimmed.startsWith('#/')) {
      headerLines.push(line);
      continue;
    }
    
    // Check if this is a key line to remove
    const keyMatch = /^(VHSM_PRIVATE_KEY[^=]*)=/.exec(trimmed);
    if (keyMatch && keysToRemoveSet.has(keyMatch[1])) {
      removedAny = true;
      continue;
    }
    
    // Keep this line
    if (trimmed) {
      remainingLines.push(line);
    }
  }
  
  // Check if there are any keys remaining
  const remainingKeys = parseEncryptedKeys(remainingLines.join('\n'));
  const shouldDelete = remainingKeys.length === 0;
  
  if (removedAny) {
    if (shouldDelete) {
      unlinkSync(filePath);
    } else {
      const newContent = headerLines.length > 0 
        ? headerLines.join('\n') + '\n' + remainingLines.join('\n')
        : remainingLines.join('\n');
      writeFileSync(filePath, newContent, { mode: 0o600 });
    }
  }
  
  return { removed: removedAny, shouldDelete };
}

/**
 * Check if a pattern exists in .gitignore
 */
export function isPatternInGitignore(pattern: string, gitignorePath: string = '.gitignore'): boolean {
  if (!existsSync(gitignorePath)) {
    return false;
  }
  
  const content = readFileSync(gitignorePath, 'utf-8');
  const lines = content.split('\n');
  
  // Normalize pattern for comparison (remove leading/trailing whitespace)
  const normalizedPattern = pattern.trim();
  
  for (const line of lines) {
    const trimmed = line.trim();
    // Check for exact match or if the line contains the pattern
    // Also handle patterns with wildcards or path separators
    if (trimmed === normalizedPattern || 
        trimmed === `/${normalizedPattern}` ||
        trimmed.endsWith(normalizedPattern) ||
        trimmed.includes(normalizedPattern)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Add a pattern to .gitignore
 */
export function addPatternToGitignore(pattern: string, gitignorePath: string = '.gitignore'): void {
  let content = '';
  
  if (existsSync(gitignorePath)) {
    content = readFileSync(gitignorePath, 'utf-8');
    // Ensure file ends with newline
    if (!content.endsWith('\n')) {
      content += '\n';
    }
  }
  
  // Add the pattern
  content += `${pattern}\n`;
  
  writeFileSync(gitignorePath, content, { mode: 0o644 });
}

/**
 * Remove header, public key, and filename comment from .env file
 * Removes everything from the first #/ line up to and including the first # .env* comment
 */
export function removeHeaderAndPublicKeyFromEnvFile(filePath: string): { removed: boolean } {
  if (!existsSync(filePath)) {
    return { removed: false };
  }
  
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const remainingLines: string[] = [];
  let removedAny = false;
  let inHeaderSection = true;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    if (inHeaderSection) {
      // Skip header lines (starting with #/)
      if (trimmed.startsWith('#/')) {
        removedAny = true;
        continue;
      }
      
      // Skip public key line (DOTENV_PUBLIC_KEY or DOTENV_PUBLIC_KEY_*)
      if (/^DOTENV_PUBLIC_KEY[^=]*=/.test(trimmed)) {
        removedAny = true;
        continue;
      }
      
      // Skip empty lines in the header section
      if (!trimmed) {
        removedAny = true;
        continue;
      }
      
      // Skip filename comment (e.g., "# .env.local" or "# .env")
      // This marks the end of the header section
      if (trimmed.startsWith('#') && /^#\s*\.env/.test(trimmed)) {
        removedAny = true;
        inHeaderSection = false; // End of header section, start keeping lines
        continue;
      }
    }
    
    // Keep all lines after the header section
    remainingLines.push(line);
  }
  
  if (removedAny) {
    // Write back the cleaned content, preserving trailing newlines
    const newContent = remainingLines.join('\n');
    writeFileSync(filePath, newContent, { mode: 0o644 });
  }
  
  return { removed: removedAny };
}

export function jsonFileToEnvKey(filePath: string): string {
  const fileName = basename(filePath, '.json');
  return fileName.toUpperCase().replace(/[^A-Z0-9]/g, '_') + '_JSON';
}