const { initializeAdmin } = require('./server');

function readArg(name) {
  const prefix = `--${name}=`;
  const arg = process.argv.find((item) => item.startsWith(prefix));
  return arg ? arg.slice(prefix.length) : null;
}

const password = readArg('password');
const force = process.argv.includes('--force');

if (!password) {
  console.error('Usage: node init-admin.js --password="a-long-password" [--force]');
  process.exit(1);
}

if (password.length < 12) {
  console.error('Password must be at least 12 characters.');
  process.exit(1);
}

try {
  const admin = initializeAdmin(password, force);
  console.log(JSON.stringify({
    message: force ? 'Admin account reset.' : 'Admin account initialized.',
    createdAt: admin.createdAt,
    totpEnabled: Boolean(admin.totp)
  }, null, 2));
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
