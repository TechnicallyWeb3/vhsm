import { readFileSync } from 'node:fs';

const keyFile = readFileSync('test-app/.env.keys', 'utf-8');
console.log('Full file content:');
console.log(keyFile);
console.log('\n---\n');

// Extract just the DOTENV_PRIVATE_KEY value
const lines = keyFile.split('\n');
const keyLine = lines.find(line => line.startsWith('DOTENV_PRIVATE_KEY='));
if (keyLine) {
  const keyValue = keyLine.split('=')[1];
  console.log('Extracted key value:', keyValue);
} else {
  console.log('No DOTENV_PRIVATE_KEY found');
}

