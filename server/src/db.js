const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const db = new Database(process.env.DB_PATH || path.join(__dirname, '..', 'geeken.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  email TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('theme','both')),
  status TEXT NOT NULL DEFAULT 'active',
  domain TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_hash TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
`);

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function randomChunk(n) {
  const bytes = crypto.randomBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += ALPHABET[bytes[i] % ALPHABET.length];
  return s;
}
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const normDomain = (d) => String(d || '').trim().toLowerCase();

function createLicense({ email, type, days }) {
  const key = ['GKN', randomChunk(4), randomChunk(4), randomChunk(4), randomChunk(4)].join('-');
  const now = Date.now();
  const expires = days > 0 ? now + days * 86400000 : null;
  db.prepare('INSERT INTO licenses (key,email,type,created_at,expires_at) VALUES (?,?,?,?,?)')
    .run(key, email, type, now, expires);
  return getLicense(key);
}
const getLicense = (key) => db.prepare('SELECT * FROM licenses WHERE key = ?').get(String(key || ''));
const listLicenses = () => db.prepare('SELECT * FROM licenses ORDER BY id DESC LIMIT 500').all();
const revokeLicense = (key) => db.prepare("UPDATE licenses SET status='revoked' WHERE key=?").run(key).changes;
const deleteLicense = (key) => db.prepare('DELETE FROM licenses WHERE key=?').run(key).changes;
const resetDomain = (key) => db.prepare('UPDATE licenses SET domain=NULL WHERE key=?').run(key).changes;

function verify(key, domain, product) {
  const l = getLicense(key);
  const d = normDomain(domain);
  if (!l) return { ok: false, error: 'Invalid license key' };
  if (l.status !== 'active') return { ok: false, error: 'This license was revoked' };
  if (l.expires_at && l.expires_at < Date.now()) return { ok: false, error: 'This license expired' };
  if (product === 'addon' && l.type !== 'both') return { ok: false, error: 'This license does not include addons' };
  if (!d) return { ok: false, error: 'Domain is required' };
  if (!l.domain) db.prepare('UPDATE licenses SET domain=? WHERE id=?').run(d, l.id);
  else if (l.domain !== d) return { ok: false, error: 'This license is locked to ' + l.domain };
  return { ok: true, type: l.type };
}

function createApiKey(name) {
  const key = 'gk_live_' + crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO api_keys (name,key_hash,created_at) VALUES (?,?,?)').run(name, sha256(key), Date.now());
  return key;
}
const listApiKeys = () => db.prepare('SELECT id,name,created_at,revoked FROM api_keys ORDER BY id DESC').all();
const revokeApiKey = (id) => db.prepare('UPDATE api_keys SET revoked=1 WHERE id=?').run(id).changes;
const apiKeyValid = (key) => !!db.prepare('SELECT 1 FROM api_keys WHERE key_hash=? AND revoked=0').get(sha256(String(key || '')));

module.exports = {
  createLicense, getLicense, listLicenses, revokeLicense, deleteLicense, resetDomain, verify,
  createApiKey, listApiKeys, revokeApiKey, apiKeyValid, normDomain,
};
