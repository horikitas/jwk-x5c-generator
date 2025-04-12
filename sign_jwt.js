const fs = require('fs');
globalThis.crypto = require('crypto').webcrypto;

(async () => {
  const jose = await import('jose');
  const { importJWK, SignJWT } = jose;
  const args = require('minimist')(process.argv.slice(2));

  // Require `--jwk` argument
  if (!args.jwk) {
    console.error(`ERROR: Missing required argument: --jwk <path_to_private_jwk.json>

  Usage:
    node sign_jwt.js --jwk ./jwk_full.json`);
    process.exit(1);
  }

  const jwkPath = args.jwk;

  (async () => {
    try {
      // Read and parse JWK
      const jwk = JSON.parse(fs.readFileSync(jwkPath, 'utf8'));

      // Import as key for signing
      const privateKey = await importJWK(jwk, 'RS256');

      // Define payload
      const payload = {
        sub: 'suzune.horikita',
        role: 'admin',
        exp: Math.floor(Date.now() / 1000) + 60 * 10, // 10 mins
      };

      // Sign JWT
      const token = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'RS256', kid: jwk.kid || 'demo-key' })
        .setIssuedAt()
        .setExpirationTime('10m')
        .sign(privateKey);

      console.log('SUCCESS: Signed JWT:\n');
      console.log(token);
    } catch (err) {
      console.error('ERROR: Failed to sign JWT:', err.message);
      process.exit(1);
    }
  })();

})();

