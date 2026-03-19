const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { DatabaseSync } = require('node:sqlite');
const QRCode = require('qrcode');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const STEP_SECONDS = 30;
const DIGITS = 6;
const ISSUER = process.env.TOTP_ISSUER || 'Personal Internal TOTP';
const COOKIE_NAME = 'demo_session';
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'app.db');
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const ENROLLMENT_TTL_MS = 10 * 60 * 1000;

const sessions = new Map();
const loginChallenges = new Map();
const db = openDatabase();
const MASTER_KEY = getOrCreateMasterKey();

function nowIso() {
  return new Date().toISOString();
}

function openDatabase() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const database = new DatabaseSync(DB_FILE);
  database.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS admin (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_password_change_at TEXT NOT NULL,
      last_recovery_login_at TEXT,
      totp_secret_json TEXT,
      totp_enabled_at TEXT,
      pending_secret_json TEXT,
      pending_expires_at TEXT,
      recovery_codes_json TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      event_type TEXT NOT NULL,
      success INTEGER NOT NULL,
      detail_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS totp_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      issuer TEXT NOT NULL,
      account_name TEXT NOT NULL,
      secret_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  return database;
}

function getOrCreateMasterKey() {
  if (process.env.MASTER_KEY) {
    return deriveMasterKey(process.env.MASTER_KEY);
  }

  fs.mkdirSync(DATA_DIR, { recursive: true });
  const keyFile = path.join(DATA_DIR, 'master.key');
  if (fs.existsSync(keyFile)) {
    return deriveMasterKey(fs.readFileSync(keyFile, 'utf8').trim());
  }

  const generated = crypto.randomBytes(32).toString('base64url');
  fs.writeFileSync(keyFile, generated, { mode: 0o600 });
  return deriveMasterKey(generated);
}

function deriveMasterKey(input) {
  const normalized = String(input).trim();
  if (!normalized) {
    throw new Error('MASTER_KEY is empty.');
  }
  return crypto.createHash('sha256').update(normalized).digest();
}

function logAudit(eventType, success, detail = {}) {
  db.prepare(`
    INSERT INTO audit_logs (created_at, event_type, success, detail_json)
    VALUES (?, ?, ?, ?)
  `).run(nowIso(), eventType, success ? 1 : 0, JSON.stringify(detail));
}

function parseAdminRow(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    passwordHash: row.password_hash,
    createdAt: row.created_at,
    lastPasswordChangeAt: row.last_password_change_at,
    lastRecoveryLoginAt: row.last_recovery_login_at,
    totp: row.totp_secret_json ? {
      secret: JSON.parse(row.totp_secret_json),
      enabledAt: row.totp_enabled_at,
      issuer: ISSUER,
      digits: DIGITS,
      period: STEP_SECONDS
    } : null,
    pendingEnrollment: row.pending_secret_json ? {
      secret: JSON.parse(row.pending_secret_json),
      expiresAt: row.pending_expires_at
    } : null,
    recoveryCodes: JSON.parse(row.recovery_codes_json || '[]')
  };
}

function getAdmin() {
  const row = db.prepare('SELECT * FROM admin WHERE id = 1').get();
  return parseAdminRow(row);
}

function parseTotpEntryRow(row, timestamp = Date.now()) {
  if (!row) {
    return null;
  }

  const secret = decryptSecret(JSON.parse(row.secret_json));
  const secondsIntoStep = Math.floor(timestamp / 1000) % STEP_SECONDS;
  return {
    id: row.id,
    issuer: row.issuer,
    account: row.account_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    secretPreview: secret.slice(0, 4) + '...' + secret.slice(-4),
    currentCode: totp(secret, timestamp, STEP_SECONDS, DIGITS),
    secondsRemaining: STEP_SECONDS - secondsIntoStep
  };
}

function listTotpEntries(timestamp = Date.now()) {
  return db.prepare(`
    SELECT id, issuer, account_name, secret_json, created_at, updated_at
    FROM totp_entries
    ORDER BY issuer COLLATE NOCASE ASC, account_name COLLATE NOCASE ASC, id ASC
  `).all().map((row) => parseTotpEntryRow(row, timestamp));
}

function createTotpEntry({ issuer, account, secret }) {
  const normalizedIssuer = String(issuer || '').trim();
  const normalizedAccount = String(account || '').trim();
  const normalizedSecret = normalizeBase32Secret(secret);
  const createdAt = nowIso();

  const result = db.prepare(`
    INSERT INTO totp_entries (issuer, account_name, secret_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    normalizedIssuer,
    normalizedAccount,
    JSON.stringify(encryptSecret(normalizedSecret)),
    createdAt,
    createdAt
  );

  return db.prepare(`
    SELECT id, issuer, account_name, secret_json, created_at, updated_at
    FROM totp_entries
    WHERE id = ?
  `).get(result.lastInsertRowid);
}

function adminExists() {
  return Boolean(db.prepare('SELECT id FROM admin WHERE id = 1').get());
}

function upsertAdmin(admin) {
  db.prepare(`
    INSERT INTO admin (
      id, password_hash, created_at, last_password_change_at, last_recovery_login_at,
      totp_secret_json, totp_enabled_at, pending_secret_json, pending_expires_at, recovery_codes_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      password_hash = excluded.password_hash,
      created_at = excluded.created_at,
      last_password_change_at = excluded.last_password_change_at,
      last_recovery_login_at = excluded.last_recovery_login_at,
      totp_secret_json = excluded.totp_secret_json,
      totp_enabled_at = excluded.totp_enabled_at,
      pending_secret_json = excluded.pending_secret_json,
      pending_expires_at = excluded.pending_expires_at,
      recovery_codes_json = excluded.recovery_codes_json
  `).run(
    1,
    admin.passwordHash,
    admin.createdAt,
    admin.lastPasswordChangeAt,
    admin.lastRecoveryLoginAt,
    admin.totp ? JSON.stringify(admin.totp.secret) : null,
    admin.totp ? admin.totp.enabledAt : null,
    admin.pendingEnrollment ? JSON.stringify(admin.pendingEnrollment.secret) : null,
    admin.pendingEnrollment ? admin.pendingEnrollment.expiresAt : null,
    JSON.stringify(admin.recoveryCodes || [])
  );
}

function listRecentAuditLogs(limit = 20) {
  return db.prepare(`
    SELECT created_at, event_type, success, detail_json
    FROM audit_logs
    ORDER BY id DESC
    LIMIT ?
  `).all(limit).map((row) => ({
    createdAt: row.created_at,
    eventType: row.event_type,
    success: Boolean(row.success),
    detail: JSON.parse(row.detail_json)
  }));
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(body);
}

function sendText(res, statusCode, text, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(statusCode, {
    'Content-Type': contentType,
    'Content-Length': Buffer.byteLength(text)
  });
  res.end(text);
}

function notFound(res) {
  sendJson(res, 404, { error: 'Not found' });
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function randomId(bytes = 24) {
  return crypto.randomBytes(bytes).toString('hex');
}

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

function base32Decode(input) {
  const normalized = input.toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  let bits = '';

  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base32 character: ${char}`);
    }
    bits += index.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return Buffer.from(bytes);
}

function generateSecret(lengthBytes = 20) {
  return base32Encode(crypto.randomBytes(lengthBytes));
}

function normalizeBase32Secret(value) {
  const normalized = String(value || '').toUpperCase().replace(/\s+/g, '').replace(/=+$/g, '');
  if (normalized.length < 16) {
    throw new Error('Secret must be at least 16 base32 characters.');
  }
  base32Decode(normalized);
  return normalized;
}

function normalizeTotpCode(value) {
  return String(value || '').replace(/\D/g, '').slice(0, DIGITS);
}

function hotp(secret, counter, digits = DIGITS) {
  const key = base32Decode(secret);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

function totp(secret, timestamp = Date.now(), stepSeconds = STEP_SECONDS, digits = DIGITS) {
  const counter = Math.floor(timestamp / 1000 / stepSeconds);
  return hotp(secret, counter, digits);
}

function verifyTotp(secret, code, { window = 1, timestamp = Date.now() } = {}) {
  const normalizedCode = normalizeTotpCode(code);
  if (normalizedCode.length !== DIGITS) {
    return false;
  }

  const baseCounter = Math.floor(timestamp / 1000 / STEP_SECONDS);
  for (let drift = -window; drift <= window; drift += 1) {
    if (hotp(secret, baseCounter + drift, DIGITS) === normalizedCode) {
      return true;
    }
  }
  return false;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const iterations = 210_000;
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256').toString('hex');
  return `${iterations}:${salt}:${hash}`;
}

function verifyPassword(password, storedValue) {
  const [iterationsText, salt, expected] = String(storedValue).split(':');
  const iterations = Number(iterationsText);
  if (!iterations || !salt || !expected) {
    return false;
  }
  const actual = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256').toString('hex');
  const actualBuffer = Buffer.from(actual, 'hex');
  const expectedBuffer = Buffer.from(expected, 'hex');
  return actualBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function hashRecoveryCode(code, salt = crypto.randomBytes(16).toString('hex')) {
  const iterations = 120_000;
  const normalized = code.trim().toUpperCase();
  const hash = crypto.pbkdf2Sync(normalized, salt, iterations, 32, 'sha256').toString('hex');
  return `${iterations}:${salt}:${hash}`;
}

function verifyRecoveryCode(code, storedValue) {
  return verifyPassword(String(code || '').trim().toUpperCase(), storedValue);
}

function encryptSecret(secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: encrypted.toString('base64')
  };
}

function decryptSecret(payload) {
  if (!payload || !payload.iv || !payload.tag || !payload.ciphertext) {
    throw new Error('Encrypted secret is missing or malformed.');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, 'base64')),
    decipher.final()
  ]);
  return decrypted.toString('utf8');
}

function generateRecoveryCodes() {
  return Array.from({ length: 8 }, () => crypto.randomBytes(5).toString('hex').toUpperCase());
}

function hashRecoveryCodes(codes) {
  return codes.map((code) => hashRecoveryCode(code));
}

function createOtpauthUrl(secret) {
  const label = encodeURIComponent(`${ISSUER}:admin`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}

async function createQrSvg(otpauthUrl) {
  return QRCode.toString(otpauthUrl, {
    type: 'svg',
    errorCorrectionLevel: 'M',
    margin: 1,
    width: 220,
    color: {
      dark: '#1d2935',
      light: '#fffaf0'
    }
  });
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return header.split(';').reduce((acc, pair) => {
    const [key, ...rest] = pair.trim().split('=');
    if (!key) {
      return acc;
    }
    acc[key] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function createSession({ usedRecoveryCode = false, bootstrap = false } = {}) {
  const sessionId = randomId(18);
  const session = {
    sessionId,
    createdAt: nowIso(),
    expiresAt: Date.now() + SESSION_TTL_MS,
    usedRecoveryCode,
    bootstrap
  };
  sessions.set(sessionId, session);
  return session;
}

function cleanupSessions() {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (session.expiresAt <= now) {
      sessions.delete(id);
    }
  }
}

function setSessionCookie(res, sessionId) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${sessionId}; HttpOnly; Path=/; SameSite=Lax`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}

function getCurrentSession(req) {
  cleanupSessions();
  const cookies = parseCookies(req);
  const sessionId = cookies[COOKIE_NAME];
  if (!sessionId) {
    return null;
  }
  return sessions.get(sessionId) || null;
}

async function buildEnrollmentView(admin) {
  if (!admin?.pendingEnrollment) {
    return null;
  }
  const secret = decryptSecret(admin.pendingEnrollment.secret);
  const otpauthUrl = createOtpauthUrl(secret);
  return {
    startedAt: admin.pendingEnrollment.startedAt,
    expiresAt: admin.pendingEnrollment.expiresAt,
    secretPreview: secret.slice(0, 4) + '...' + secret.slice(-4),
    otpauthUrl,
    qrSvg: await createQrSvg(otpauthUrl)
  };
}

function sanitizeAdmin(admin, session = null) {
  return {
    initialized: Boolean(admin),
    createdAt: admin?.createdAt || null,
    totpEnabled: Boolean(admin?.totp),
    recoveryCodesRemaining: admin?.recoveryCodes?.length || 0,
    lastPasswordChangeAt: admin?.lastPasswordChangeAt || null,
    lastRecoveryLoginAt: admin?.lastRecoveryLoginAt || null,
    session: session ? {
      bootstrap: session.bootstrap,
      usedRecoveryCode: session.usedRecoveryCode,
      createdAt: session.createdAt,
      expiresAt: new Date(session.expiresAt).toISOString()
    } : null
  };
}

function requireSession(req, res) {
  const session = getCurrentSession(req);
  if (!session) {
    sendJson(res, 401, { error: 'Not authenticated.' });
    return null;
  }
  const admin = getAdmin();
  if (!admin) {
    sessions.delete(session.sessionId);
    clearSessionCookie(res);
    sendJson(res, 401, { error: 'Administrator account is not initialized.' });
    return null;
  }
  return { session, admin };
}

function cleanupChallenges() {
  const now = Date.now();
  for (const [id, challenge] of loginChallenges.entries()) {
    if (challenge.expiresAt <= now) {
      loginChallenges.delete(id);
    }
  }
}

function cleanupExpiredEnrollments() {
  const admin = getAdmin();
  if (!admin?.pendingEnrollment) {
    return;
  }
  if (new Date(admin.pendingEnrollment.expiresAt).getTime() <= Date.now()) {
    admin.pendingEnrollment = null;
    upsertAdmin(admin);
    logAudit('totp_enrollment_expired', true, {});
  }
}

setInterval(cleanupChallenges, 60_000).unref();
setInterval(cleanupSessions, 60_000).unref();
setInterval(cleanupExpiredEnrollments, 60_000).unref();

async function beginEnrollment(admin) {
  const secret = generateSecret();
  admin.pendingEnrollment = {
    secret: encryptSecret(secret),
    startedAt: nowIso(),
    expiresAt: new Date(Date.now() + ENROLLMENT_TTL_MS).toISOString()
  };
  upsertAdmin(admin);
  logAudit('totp_enrollment_started', true, {});
  return buildEnrollmentView(admin);
}

function finalizeEnrollment(admin, secret) {
  const recoveryCodes = generateRecoveryCodes();
  admin.totp = {
    secret: encryptSecret(secret),
    enabledAt: nowIso(),
    issuer: ISSUER,
    digits: DIGITS,
    period: STEP_SECONDS
  };
  admin.pendingEnrollment = null;
  admin.recoveryCodes = hashRecoveryCodes(recoveryCodes);
  admin.lastRecoveryLoginAt = null;
  upsertAdmin(admin);
  logAudit('totp_enrollment_confirmed', true, { recoveryCodesGenerated: recoveryCodes.length });
  return recoveryCodes;
}

function consumeRecoveryCode(admin, code) {
  const index = admin.recoveryCodes.findIndex((item) => verifyRecoveryCode(code, item));
  if (index === -1) {
    return false;
  }
  admin.recoveryCodes.splice(index, 1);
  admin.lastRecoveryLoginAt = nowIso();
  upsertAdmin(admin);
  logAudit('recovery_code_login', true, { recoveryCodesRemaining: admin.recoveryCodes.length });
  return true;
}

function getAdminSecret(admin) {
  if (!admin.totp?.secret) {
    throw new Error('TOTP is not enabled.');
  }
  return decryptSecret(admin.totp.secret);
}

async function handleApi(req, res, url) {
  if (req.method === 'GET' && url.pathname === '/api/status') {
    const admin = getAdmin();
    sendJson(res, 200, {
      initialized: Boolean(admin),
      totpEnabled: Boolean(admin?.totp)
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/login/password') {
    const admin = getAdmin();
    if (!admin) {
      sendJson(res, 409, { error: 'Admin account is not initialized. Run npm run init-admin first.' });
      return;
    }

    const body = await parseJsonBody(req);
    const password = String(body.password || '');
    if (!verifyPassword(password, admin.passwordHash)) {
      logAudit('password_login', false, { reason: 'bad_password' });
      sendJson(res, 401, { error: 'Invalid password.' });
      return;
    }

    if (!admin.totp) {
      const session = createSession({ bootstrap: true });
      setSessionCookie(res, session.sessionId);
      logAudit('password_login', true, { bootstrap: true });
      sendJson(res, 200, {
        message: 'Password verified. TOTP enrollment is still required for this admin account.',
        admin: {
          ...sanitizeAdmin(admin, session),
          pendingEnrollment: await buildEnrollmentView(admin)
        }
      });
      return;
    }

    const challengeId = randomId(16);
    loginChallenges.set(challengeId, { expiresAt: Date.now() + CHALLENGE_TTL_MS });
    logAudit('password_login', true, { bootstrap: false });
    sendJson(res, 200, {
      message: 'Password verified. Enter a TOTP code or a recovery code.',
      challengeId,
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString()
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/login/totp') {
    const admin = getAdmin();
    if (!admin || !admin.totp) {
      sendJson(res, 409, { error: 'TOTP is not enabled for the admin account.' });
      return;
    }

    const body = await parseJsonBody(req);
    const challengeId = String(body.challengeId || '');
    const code = String(body.code || '').trim();
    const challenge = loginChallenges.get(challengeId);

    if (!challenge || challenge.expiresAt <= Date.now()) {
      loginChallenges.delete(challengeId);
      logAudit('totp_login', false, { reason: 'expired_challenge' });
      sendJson(res, 401, { error: 'Challenge expired. Start login again.' });
      return;
    }

    let usedRecoveryCode = false;
    if (!verifyTotp(getAdminSecret(admin), code)) {
      if (!consumeRecoveryCode(admin, code)) {
        logAudit('totp_login', false, { reason: 'invalid_code' });
        sendJson(res, 401, { error: 'Invalid TOTP or recovery code.' });
        return;
      }
      usedRecoveryCode = true;
    }

    loginChallenges.delete(challengeId);
    const session = createSession({ usedRecoveryCode, bootstrap: false });
    setSessionCookie(res, session.sessionId);
    logAudit('totp_login', true, { usedRecoveryCode });
    sendJson(res, 200, {
      message: usedRecoveryCode ? 'Logged in with a recovery code. Re-enroll TOTP on this device.' : 'Logged in with TOTP.',
      admin: {
        ...sanitizeAdmin(getAdmin(), session),
        pendingEnrollment: await buildEnrollmentView(getAdmin())
      }
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/me') {
    const auth = requireSession(req, res);
    if (!auth) {
      return;
    }
    sendJson(res, 200, {
      authenticated: true,
      admin: {
        ...sanitizeAdmin(auth.admin, auth.session),
        pendingEnrollment: await buildEnrollmentView(auth.admin)
      },
      auditLogs: listRecentAuditLogs(12)
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/totp-entries') {
    const auth = requireSession(req, res);
    if (!auth) {
      return;
    }

    sendJson(res, 200, {
      entries: listTotpEntries(Date.now())
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/totp-entries') {
    const auth = requireSession(req, res);
    if (!auth) {
      return;
    }

    const body = await parseJsonBody(req);
    const issuer = String(body.issuer || '').trim();
    const account = String(body.account || '').trim();
    const secret = String(body.secret || '').trim();

    if (!issuer) {
      sendJson(res, 400, { error: 'Issuer is required.' });
      return;
    }
    if (!account) {
      sendJson(res, 400, { error: 'Account is required.' });
      return;
    }
    if (!secret) {
      sendJson(res, 400, { error: 'Secret is required.' });
      return;
    }

    try {
      const entry = parseTotpEntryRow(createTotpEntry({ issuer, account, secret }));
      logAudit('totp_entry_created', true, { issuer, account, entryId: entry.id });
      sendJson(res, 201, {
        message: 'TOTP entry saved.',
        entry
      });
    } catch (error) {
      logAudit('totp_entry_created', false, { issuer, account, reason: 'invalid_secret' });
      sendJson(res, 400, { error: error.message || 'Secret is invalid.' });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/account/totp/enroll') {
    const auth = requireSession(req, res);
    if (!auth) {
      return;
    }
    const enrollment = await beginEnrollment(auth.admin);
    sendJson(res, 200, {
      message: 'Scan the QR code and confirm one current TOTP code.',
      enrollment,
      admin: {
        ...sanitizeAdmin(auth.admin, auth.session),
        pendingEnrollment: enrollment
      }
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/account/totp/confirm') {
    const auth = requireSession(req, res);
    if (!auth) {
      return;
    }

    const body = await parseJsonBody(req);
    const code = String(body.code || '').trim();
    const pendingEnrollment = auth.admin.pendingEnrollment;
    if (!pendingEnrollment) {
      sendJson(res, 400, { error: 'No pending enrollment exists.' });
      return;
    }
    if (new Date(pendingEnrollment.expiresAt).getTime() <= Date.now()) {
      auth.admin.pendingEnrollment = null;
      upsertAdmin(auth.admin);
      logAudit('totp_enrollment_confirmed', false, { reason: 'expired_pending' });
      sendJson(res, 400, { error: 'Enrollment expired. Start again.' });
      return;
    }

    const pendingSecret = decryptSecret(pendingEnrollment.secret);
    if (!verifyTotp(pendingSecret, code)) {
      logAudit('totp_enrollment_confirmed', false, { reason: 'invalid_code' });
      sendJson(res, 401, { error: 'Invalid TOTP code for the pending enrollment.' });
      return;
    }

    const recoveryCodes = finalizeEnrollment(auth.admin, pendingSecret);
    auth.session.bootstrap = false;
    auth.session.usedRecoveryCode = false;
    sendJson(res, 200, {
      message: 'TOTP is now enabled. Store the recovery codes securely.',
      admin: {
        ...sanitizeAdmin(getAdmin(), auth.session),
        pendingEnrollment: null
      },
      recoveryCodes
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/account/recovery-codes/regenerate') {
    const auth = requireSession(req, res);
    if (!auth) {
      return;
    }

    const body = await parseJsonBody(req);
    const password = String(body.password || '');
    if (!verifyPassword(password, auth.admin.passwordHash)) {
      logAudit('recovery_codes_rotated', false, { reason: 'bad_password' });
      sendJson(res, 401, { error: 'Password confirmation failed.' });
      return;
    }
    if (!auth.admin.totp) {
      sendJson(res, 400, { error: 'Enable TOTP before generating recovery codes.' });
      return;
    }

    const recoveryCodes = generateRecoveryCodes();
    auth.admin.recoveryCodes = hashRecoveryCodes(recoveryCodes);
    upsertAdmin(auth.admin);
    logAudit('recovery_codes_rotated', true, { recoveryCodesGenerated: recoveryCodes.length });

    sendJson(res, 200, {
      message: 'Recovery codes rotated. Old recovery codes are now invalid.',
      admin: {
        ...sanitizeAdmin(getAdmin(), auth.session),
        pendingEnrollment: await buildEnrollmentView(getAdmin())
      },
      recoveryCodes
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/account/password/change') {
    const auth = requireSession(req, res);
    if (!auth) {
      return;
    }
    const body = await parseJsonBody(req);
    const currentPassword = String(body.currentPassword || '');
    const nextPassword = String(body.nextPassword || '');
    if (!verifyPassword(currentPassword, auth.admin.passwordHash)) {
      logAudit('password_changed', false, { reason: 'bad_current_password' });
      sendJson(res, 401, { error: 'Current password is incorrect.' });
      return;
    }
    if (nextPassword.length < 12) {
      sendJson(res, 400, { error: 'New password must be at least 12 characters.' });
      return;
    }
    auth.admin.passwordHash = hashPassword(nextPassword);
    auth.admin.lastPasswordChangeAt = nowIso();
    upsertAdmin(auth.admin);
    logAudit('password_changed', true, {});
    sendJson(res, 200, {
      message: 'Password updated.',
      admin: {
        ...sanitizeAdmin(getAdmin(), auth.session),
        pendingEnrollment: await buildEnrollmentView(getAdmin())
      }
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/logout') {
    const session = getCurrentSession(req);
    if (session) {
      sessions.delete(session.sessionId);
    }
    clearSessionCookie(res);
    logAudit('logout', true, {});
    sendJson(res, 200, { message: 'Logged out.' });
    return;
  }

  notFound(res);
}

function serveStaticFile(res, pathname) {
  const relativePath = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.join(__dirname, 'public', path.normalize(relativePath));
  const publicRoot = path.join(__dirname, 'public');

  if (!filePath.startsWith(publicRoot)) {
    notFound(res);
    return;
  }

  fs.readFile(filePath, (err, content) => {
    if (err) {
      notFound(res);
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentTypes = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml; charset=utf-8'
    };
    sendText(res, 200, content, contentTypes[ext] || 'application/octet-stream');
  });
}

function createAppServer() {
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://${req.headers.host}`);

      if (url.pathname.startsWith('/api/')) {
        await handleApi(req, res, url);
        return;
      }

      if (req.method === 'GET') {
        serveStaticFile(res, url.pathname);
        return;
      }

      notFound(res);
    } catch (error) {
      sendJson(res, 500, { error: error.message || 'Internal server error' });
    }
  });
}

if (require.main === module) {
  const server = createAppServer();
  server.listen(PORT, HOST, () => {
    console.log(`TOTP demo listening on http://${HOST}:${PORT}`);
  });
}

module.exports = {
  DB_FILE,
  createAppServer,
  createOtpauthUrl,
  db,
  encryptSecret,
  decryptSecret,
  generateSecret,
  getAdmin,
  hashPassword,
  hotp,
  initializeAdmin: function initializeAdmin(password, force = false) {
    const existing = getAdmin();
    if (existing && !force) {
      throw new Error('Admin account already exists. Use --force to replace it.');
    }
    const admin = {
      passwordHash: hashPassword(password),
      createdAt: existing?.createdAt || nowIso(),
      lastPasswordChangeAt: nowIso(),
      lastRecoveryLoginAt: null,
      totp: null,
      pendingEnrollment: null,
      recoveryCodes: []
    };
    upsertAdmin(admin);
    logAudit('admin_initialized', true, { force });
    return getAdmin();
  },
  listRecentAuditLogs,
  totp,
  verifyPassword,
  verifyTotp
};
