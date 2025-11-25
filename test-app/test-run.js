console.log('✅ Success! VHSM decrypted the keys and loaded environment variables.');
console.log('Environment variables loaded:', Object.keys(process.env).filter(k => k.includes('TEST') || k.includes('PORT')).length);

