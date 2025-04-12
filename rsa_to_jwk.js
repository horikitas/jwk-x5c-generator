const fs = require('fs');
const jose = require('node-jose');
const { spawnSync } = require('child_process');
const args = require('minimist')(process.argv.slice(2));

// Enforce required flags
if (!args.key || !args.cert || !args['out-full'] || !args['out-public']) {
  console.error(`Missing required arguments.
Usage:
  node rsa_to_jwk.js \\
    --key <private_key.pem> \\
    --cert <cert.pem> \\
    --out-full <output_full_jwk.json> \\
    --out-public <output_public_jwk.json>

Example:
  node rsa_to_jwk.js \\
    --key ./rsa/private_key.pem \\
    --cert ./rsa/cert.pem \\
    --out-full ./out/jwk_full.json \\
    --out-public ./out/jwk_public.json
`);
  process.exit(1);
}

const keyPath = args.key;
const certPath = args.cert;
const outFull = args['out-full'];
const outPublic = args['out-public'];

(async () => {
  try {
    // Load private key
    const keyPem = fs.readFileSync(keyPath, 'utf8');

    // Convert cert to DER + base64 for x5c
    const result = spawnSync('openssl', ['x509', '-in', certPath, '-outform', 'DER']);
    if (result.status !== 0) {
      throw new Error(`OpenSSL error: ${result.stderr.toString()}`);
    }
    const certDerBase64 = result.stdout.toString('base64').replace(/\n/g, '');

    // Create JWK
    const keystore = jose.JWK.createKeyStore();
    const key = await keystore.add(keyPem, 'pem');

    // Build full JWK with private fields
    const jwkFull = key.toJSON(true);
    jwkFull.x5c = [certDerBase64];
    fs.writeFileSync(outFull, JSON.stringify(jwkFull, null, 2));

    // Build public-only JWK
    const jwkPublic = key.toJSON();
    jwkPublic.x5c = [certDerBase64];
    fs.writeFileSync(outPublic, JSON.stringify(jwkPublic, null, 2));

    console.log(`JWKs generated:
- Full (private): ${outFull}
- Public-only: ${outPublic}`);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
})();
