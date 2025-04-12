globalThis.crypto = require('crypto').webcrypto;

const fs = require('fs');
const args = require('minimist')(process.argv.slice(2));

if (!args.jwt || !args.jwk) {
  console.error(`Usage:
  node verify_jwt.js --jwt <jwt_token> --jwk <public_jwk_file>

Example:
  node verify_jwt.js --jwt <paste_token_here> --jwk jwk_public_with_x5c.json`);
  process.exit(1);
}

(async () => {
  try {
    const jose = await import('jose');
    const { importJWK, jwtVerify } = jose;

    // Load JWK and token
    const jwk = JSON.parse(fs.readFileSync(args.jwk, 'utf8'));
    const token = args.jwt;

    // Import public key
    const publicKey = await importJWK(jwk, 'RS256');

    // Verify
    const { payload, protectedHeader } = await jwtVerify(token, publicKey);

    console.log('SUCCESS: JWT is valid!');
    console.log('JWT Header:', protectedHeader);
    console.log('JWT Payload:', payload);
  } catch (err) {
    console.error('ERROR: JWT verification failed:', err.message);
    process.exit(1);
  }
})();
