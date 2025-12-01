import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { VhsmConfig } from './types.js';

/**
 * Load configuration from file or environment
 */
export function loadConfig(): VhsmConfig {
  const config: VhsmConfig = {
    provider: 'password',
    cacheTimeout: 3600000, // 1 hour
    enableCache: true,
  };

  // Check for config file
  const configPaths = [
    join(process.cwd(), '.vhsmrc.json'),
    join(process.cwd(), '.vhsm.json'),
    join(process.env.HOME || process.env.USERPROFILE || '', '.vhsmrc.json'),
  ];

  for (const configPath of configPaths) {
    try {
      const content = readFileSync(configPath, 'utf-8');
      const fileConfig = JSON.parse(content);
      Object.assign(config, fileConfig);
      break;
    } catch {
      // File doesn't exist or is invalid, continue
    }
  }

  // Override with environment variables
  if (process.env.VHSM_PROVIDER) {
    config.provider = process.env.VHSM_PROVIDER;
  }
  
  if (process.env.VHSM_CACHE_TIMEOUT) {
    config.cacheTimeout = parseInt(process.env.VHSM_CACHE_TIMEOUT, 10);
  }
  
  if (process.env.VHSM_ENABLE_CACHE !== undefined) {
    config.enableCache = process.env.VHSM_ENABLE_CACHE === 'true';
  }

  if (process.env.VHSM_ALLOW_EXEC !== undefined) {
    config.allowExec = process.env.VHSM_ALLOW_EXEC === 'true';
  }
  
  if (process.env.VHSM_PASSWORD_TIMEOUT) {
    config.passwordTimeout = parseInt(process.env.VHSM_PASSWORD_TIMEOUT, 10);
  }

  return config;
}

