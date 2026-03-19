const assert = require('assert');
const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, 'data');
fs.rmSync(dataDir, { recursive: true, force: true });

const {
  DB_FILE,
  createOtpauthUrl,
  db,
  decryptSecret,
  encryptSecret,
  getAdmin,
  hotp,
  initializeAdmin,
  listRecentAuditLogs,
  totp,
  verifyPassword,
  verifyTotp
} = require('./server');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = '';
  for (const byte of buffer) {
    bits += byte.toString(2).padStart(8, '0');
  }
  let output = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    output += BASE32_ALPHABET[parseInt(chunk, 2)];
  }
  return output;
}

const secret = base32Encode(Buffer.from('12345678901234567890', 'ascii'));
const testVectors = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130']
];

for (const [seconds, expected] of testVectors) {
  assert.strictEqual(totp(secret, seconds * 1000, 30, 8), expected);
}

assert.strictEqual(verifyTotp(secret, totp(secret)), true);
assert.strictEqual(verifyTotp(secret, '000000'), false);
assert.strictEqual(hotp(secret, 1, 8), '94287082');

const encrypted = encryptSecret(secret);
assert.strictEqual(decryptSecret(encrypted), secret);
assert.ok(createOtpauthUrl(secret).includes('secret=' + secret));

initializeAdmin('correct horse battery staple');
const admin = getAdmin();
assert.ok(fs.existsSync(DB_FILE));
assert.strictEqual(verifyPassword('correct horse battery staple', admin.passwordHash), true);
assert.strictEqual(verifyPassword('wrong password', admin.passwordHash), false);
assert.ok(listRecentAuditLogs(5).some((item) => item.eventType === 'admin_initialized'));
assert.ok(db.prepare('SELECT 1 FROM admin WHERE id = 1').get());

console.log('Single-user SQLite, crypto, and TOTP tests passed.');
