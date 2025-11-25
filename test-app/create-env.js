#!/usr/bin/env node

/**
 * Helper script to create .env file for testing
 */

import { writeFileSync } from 'node:fs';

const envContent = `# Test environment variables
DATABASE_URL=postgresql://localhost:5432/testdb
API_KEY=test-api-key-12345
SECRET_TOKEN=super-secret-token-xyz
NODE_ENV=development
PORT=3000
`;

writeFileSync('.env', envContent);
console.log('✅ Created .env file');
console.log('⚠️  Remember to add .env to .gitignore!');

