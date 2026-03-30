// 30/03/2026
// v3 - fix analytics - fix hora Madrid
/**
 * WA Manager Pro — server.js
 * ═══════════════════════════════════════════════════════
 * Base de datos : PostgreSQL (via pg pool)
 * Auth          : JWT + bcryptjs
 * Tiempo real   : SSE (Server-Sent Events)
 * Integración   : Sistema externo AWS via POST /messages/incoming
 * ═══════════════════════════════════════════════════════
 */

require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const path         = require('path');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const { Pool }     = require('pg');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const speakeasy    = require('speakeasy');
const QRCode       = require('qrcode');

const app = express();

// Railway usa proxy — necesario para rate limiting y IPs correctas
app.set('trust proxy', 1);

// ─── Cabeceras de seguridad HTTP (Helmet) ─────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// ─── CORS restringido ─────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('CORS: origen no permitido'));
  },
  credentials: true,
}));

// ─── Límite de tamaño del body (50 KB) ───────────────────
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate limiting ────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: 'Demasiados intentos. Espera 15 minutos.' },
  standardHeaders: true, legacyHeaders: false,
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 200,
  message: { error: 'Demasiadas peticiones. Intenta en unos segundos.' },
  standardHeaders: true, legacyHeaders: false,
});
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000, max: 2000,
  message: { error: 'Rate limit excedido en webhook.' },
});

app.use('/api/', apiLimiter);
app.use('/messages/', webhookLimiter);
app.use('/webhook', webhookLimiter);

// ─── Cola de mensajes entrantes ───────────────────────────
// Procesa hasta 50 mensajes simultáneos, el resto espera en cola
const messageQueue   = [];
let   activeWorkers  = 0;
const MAX_WORKERS    = 50;

function enqueueMessage(task) {
  return new Promise((resolve, reject) => {
    messageQueue.push({ task, resolve, reject });
    processQueue();
  });
}

function processQueue() {
  while (activeWorkers < MAX_WORKERS && messageQueue.length > 0) {
    const { task, resolve, reject } = messageQueue.shift();
    activeWorkers++;
    task()
      .then(resolve)
      .catch(reject)
      .finally(() => { activeWorkers--; processQueue(); });
  }
}

// Log del estado de la cola cada 30s si hay actividad
setInterval(() => {
  if (messageQueue.length > 0 || activeWorkers > 0) {
    console.log(`📊 Cola: ${messageQueue.length} esperando, ${activeWorkers} procesando`);
  }
}, 30000);

// ─── Entorno ──────────────────────────────────────────────
const IS_TEST = (process.env.NODE_ENV || 'production') === 'test';

if (IS_TEST) {
  console.log('⚠️  Arrancando en modo TEST — datos de prueba, no usar en producción');
} else {
  const required = ['JWT_SECRET', 'EXTERNAL_API_KEY', 'DATABASE_URL'];
  const missing  = required.filter(k => !process.env[k]);
  if (missing.length) {
    console.error(`❌ Variables de entorno obligatorias en PROD: ${missing.join(', ')}`);
    process.exit(1);
  }
}

const PORT        = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || (IS_TEST ? 'test_secret_inseguro' : '');
const EXT_API_KEY = process.env.EXTERNAL_API_KEY || (IS_TEST ? 'test_api_key' : '');
const EXT_SEND    = process.env.EXTERNAL_SEND_URL || '';

// ─── Base de datos PostgreSQL ─────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false,
  max: 20,                // máximo 20 conexiones simultáneas
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Wrappers compatibles con el código existente
const run = async (sql, params=[]) => {
  // Convertir ? a $1, $2... (PostgreSQL usa $N en vez de ?)
  let i = 0;
  const pgSql = sql.replace(/\?/g, () => `$${++i}`);
  // Convertir sintaxis SQLite a PostgreSQL
  const pgSqlFinal = pgSql
    .replace(/INTEGER PRIMARY KEY AUTOINCREMENT/g, 'SERIAL PRIMARY KEY')
    .replace(/datetime\('now'\)/g, "NOW()")
    .replace(/INSERT OR IGNORE/g, 'INSERT')
    .replace(/ON CONFLICT DO NOTHING/g, '')
    .replace(/PRAGMA foreign_keys = ON/g, 'SET session_replication_role = DEFAULT');
  const res = await pool.query(pgSqlFinal, params);
  return { lastID: res.rows[0]?.id || null, changes: res.rowCount };
};

const get = async (sql, params=[]) => {
  let i = 0;
  const pgSql = sql.replace(/\?/g, () => `$${++i}`)
    .replace(/datetime\('now'\)/g, "NOW()")
    .replace(/date\(([^)]+)\)/g, "$1::date")
    .replace(/strftime\('%Y-%m-%d',([^)]+)\)/g, "TO_CHAR($1, 'YYYY-MM-DD')")
    .replace(/strftime\('%Y-%m',([^)]+)\)/g, "TO_CHAR($1, 'YYYY-MM')")
    .replace(/strftime\('%Y-W%W',([^)]+)\)/g, "TO_CHAR($1, 'IYYY-IW')")
    .replace(/julianday\('now'\)-julianday\(([^)]+)\)/g, "EXTRACT(EPOCH FROM (NOW()-$1))/86400")
    .replace(/CAST\(julianday\('now'\)-julianday\(([^)]+)\) AS INTEGER\)/g, "FLOOR(EXTRACT(EPOCH FROM (NOW()-$1))/86400)")
    .replace(/PRAGMA foreign_keys = ON/g, 'SET session_replication_role = DEFAULT');
  const res = await pool.query(pgSql, params);
  // Normalizar nombres de columnas (pg devuelve en minúsculas)
  return res.rows[0] ? normalizeRow(res.rows[0]) : undefined;
};

const all = async (sql, params=[]) => {
  let i = 0;
  const pgSql = sql.replace(/\?/g, () => `$${++i}`)
    .replace(/datetime\('now'\)/g, "NOW()")
    .replace(/date\(([^)]+)\)/g, "$1::date")
    .replace(/strftime\('%Y-%m-%d',([^)]+)\)/g, "TO_CHAR($1, 'YYYY-MM-DD')")
    .replace(/strftime\('%Y-%m',([^)]+)\)/g, "TO_CHAR($1, 'YYYY-MM')")
    .replace(/strftime\('%Y-W%W',([^)]+)\)/g, "TO_CHAR($1, 'IYYY-IW')")
    .replace(/julianday\('now'\)-julianday\(([^)]+)\)/g, "EXTRACT(EPOCH FROM (NOW()-$1))/86400")
    .replace(/CAST\(julianday\('now'\)-julianday\(([^)]+)\) AS INTEGER\)/g, "FLOOR(EXTRACT(EPOCH FROM (NOW()-$1))/86400)")
    .replace(/PRAGMA foreign_keys = ON/g, 'SET session_replication_role = DEFAULT');
  const res = await pool.query(pgSql, params);
  return res.rows.map(normalizeRow);
};

// Normalizar row — convertir timestamps a string ISO
function normalizeRow(row) {
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    out[k] = v instanceof Date ? v.toISOString() : v;
  }
  return out;
}

// ─── Inicializar tablas ───────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`CREATE TABLE IF NOT EXISTS agents (
      id         SERIAL PRIMARY KEY,
      username   TEXT UNIQUE NOT NULL,
      name       TEXT NOT NULL,
      role       TEXT NOT NULL DEFAULT 'agent',
      color      TEXT DEFAULT '#00e5a0',
      password   TEXT NOT NULL,
      totp_secret TEXT DEFAULT NULL,
      totp_enabled BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS wa_accounts (
      id              SERIAL PRIMARY KEY,
      agent_id        INTEGER NOT NULL REFERENCES agents(id),
      display_name    TEXT NOT NULL,
      phone_number_id TEXT NOT NULL DEFAULT '',
      wa_token        TEXT NOT NULL DEFAULT '',
      verify_token    TEXT NOT NULL DEFAULT '',
      created_at      TIMESTAMPTZ DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS contacts (
      phone        TEXT PRIMARY KEY,
      name         TEXT NOT NULL DEFAULT 'Desconocido',
      avatar       TEXT DEFAULT '??',
      email        TEXT DEFAULT '',
      client_id    TEXT DEFAULT '',
      contact_note TEXT DEFAULT '',
      tags         TEXT DEFAULT '[]',
      created_at   TIMESTAMPTZ DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS sessions (
      id              SERIAL PRIMARY KEY,
      phone           TEXT NOT NULL,
      wa_account_id   INTEGER NOT NULL,
      agent_id        INTEGER NOT NULL,
      flow            TEXT DEFAULT 'cliente',
      status          TEXT DEFAULT 'active',
      unread          INTEGER DEFAULT 1,
      preview         TEXT DEFAULT '',
      started_at      TIMESTAMPTZ DEFAULT NOW(),
      last_message_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS reviews (
      id         SERIAL PRIMARY KEY,
      session_id INTEGER NOT NULL,
      agent_id   INTEGER NOT NULL,
      quality    TEXT NOT NULL,
      note       TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS messages (
      id         SERIAL PRIMARY KEY,
      session_id INTEGER NOT NULL,
      phone      TEXT NOT NULL,
      direction  TEXT NOT NULL,
      body       TEXT NOT NULL,
      meta_id    TEXT,
      time_label TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS login_attempts (
      id         SERIAL PRIMARY KEY,
      username   TEXT NOT NULL,
      ip         TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti        TEXT PRIMARY KEY,
      revoked_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS activity_log (
      id         SERIAL PRIMARY KEY,
      agent_id   INTEGER,
      username   TEXT,
      action     TEXT NOT NULL,
      detail     TEXT DEFAULT '',
      ip         TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    // Índices
    await client.query('CREATE INDEX IF NOT EXISTS idx_sess_phone  ON sessions(phone)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_sess_agent  ON sessions(agent_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_sess_status ON sessions(status)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_msg_sess    ON messages(session_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_rev_sess    ON reviews(session_id)');

    // Migraciones para BDs existentes
    await client.query("ALTER TABLE agents ADD COLUMN IF NOT EXISTS totp_secret TEXT DEFAULT NULL");
    await client.query("ALTER TABLE agents ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE");

    await client.query('COMMIT');
    console.log('✅ Base de datos PostgreSQL lista');
  } catch(e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
  await seedAgents();
}

// ─── Crear agentes iniciales ──────────────────────────────
async function seedAgents() {
  const agentsList = [
    { u:'admin', n:'Administrador', r:'admin',  c:'#a78bfa', p: process.env.ADMIN_PASSWORD || 'admin123'  },
    { u:'angel', n:'Ángel',         r:'agent',  c:'#00e5a0', p: process.env.ANGEL_PASSWORD || 'angel123'  },
    { u:'clara', n:'Clara',         r:'agent',  c:'#f5a623', p: process.env.CLARA_PASSWORD || 'clara123'  },
  ];
  for (const a of agentsList) {
    const existing = await get('SELECT id FROM agents WHERE username=$1', [a.u]);
    if (!existing) {
      await pool.query(
        'INSERT INTO agents (username,name,role,color,password) VALUES ($1,$2,$3,$4,$5)',
        [a.u, a.n, a.r, a.c, bcrypt.hashSync(a.p, 10)]
      );
      console.log(`✅ ${a.n} creado`);
    }
  }
  const angel = await get('SELECT id FROM agents WHERE username=$1', ['angel']);
  const clara = await get('SELECT id FROM agents WHERE username=$1', ['clara']);
  for (const [agId, name, phoneId, token, verify] of [
    [angel.id, 'WhatsApp Ángel', process.env.ANGEL_PHONE_NUMBER_ID||'', process.env.ANGEL_WA_TOKEN||'', process.env.ANGEL_VERIFY_TOKEN||'verify_angel'],
    [clara.id, 'WhatsApp Clara', process.env.CLARA_PHONE_NUMBER_ID||'', process.env.CLARA_WA_TOKEN||'', process.env.CLARA_VERIFY_TOKEN||'verify_clara'],
  ]) {
    const ex = await get('SELECT id FROM wa_accounts WHERE agent_id=$1', [agId]);
    if (!ex) {
      await pool.query(
        'INSERT INTO wa_accounts (agent_id,display_name,phone_number_id,wa_token,verify_token) VALUES ($1,$2,$3,$4,$5)',
        [agId, name, phoneId, token, verify]
      );
    }
  }
}

// ─── Helpers ─────────────────────────────────────────────
function madridTime(date) {
  const d = date || new Date();
  const year = d.getUTCFullYear();
  const lastSundayMarch = new Date(Date.UTC(year, 2, 31));
  lastSundayMarch.setUTCDate(31 - lastSundayMarch.getUTCDay());
  const lastSundayOctober = new Date(Date.UTC(year, 9, 31));
  lastSundayOctober.setUTCDate(31 - lastSundayOctober.getUTCDay());
  const isSummer = d >= lastSundayMarch && d < lastSundayOctober;
  const offset = isSummer ? 2 : 1;
  return new Date(d.getTime() + offset * 3600000);
}
const nowTime = () => madridTime().toISOString().slice(11,16);
const mkAvatar = n  => (n||'??').split(' ').map(w=>w[0]||'').join('').slice(0,2).toUpperCase() || '??';
const safeJson = v  => { try { return JSON.parse(v||'[]'); } catch { return []; } };

function extractText(msg) {
  if (msg.text?.body)   return msg.text.body;
  if (msg.image)        return '[📷 Imagen]';
  if (msg.video)        return '[🎥 Vídeo]';
  if (msg.audio)        return '[🎙 Audio]';
  if (msg.document)     return `[📄 ${msg.document.filename||'Doc'}]`;
  if (msg.location)     return '[📍 Ubicación]';
  if (msg.sticker)      return '[🎨 Sticker]';
  if (msg.interactive?.button_reply) return msg.interactive.button_reply.title;
  if (msg.interactive?.list_reply)   return msg.interactive.list_reply.title;
  return `[${msg.type||'msg'}]`;
}

function periodDates(period) {
  const now   = new Date();
  const today = now.toISOString().slice(0, 10);
  if (period === 'today')   return { from: today, to: today };
  if (period === 'week')    { const d=new Date(now); d.setDate(d.getDate()-10); return { from: d.toISOString().slice(0,10), to: today }; }
  if (period === 'month')   { const d=new Date(now); d.setDate(d.getDate()-33); return { from: d.toISOString().slice(0,10), to: today }; }
  if (period === 'quarter') { const d=new Date(now); d.setDate(d.getDate()-93); return { from: d.toISOString().slice(0,10), to: today }; }
  return null;
}

async function enrichSession(row) {
  const msgs    = await all('SELECT * FROM messages WHERE session_id=$1 ORDER BY id ASC', [row.id]);
  const reviews = await all('SELECT r.*,a.name agent_name,a.color agent_color FROM reviews r JOIN agents a ON a.id=r.agent_id WHERE r.session_id=$1 ORDER BY r.id ASC', [row.id]);
  const history = await all('SELECT s.*,a.name agent_name,a.color agent_color,w.display_name wa_name FROM sessions s JOIN agents a ON a.id=s.agent_id JOIN wa_accounts w ON w.id=s.wa_account_id WHERE s.phone=$1 AND s.id!=$2 ORDER BY s.id DESC', [row.phone, row.id]);
  const allRevs = await all('SELECT r.*,a.name agent_name,a.color agent_color FROM reviews r JOIN agents a ON a.id=r.agent_id WHERE r.session_id IN (SELECT id FROM sessions WHERE phone=$1) ORDER BY r.created_at DESC', [row.phone]);
  const lastRev = reviews[reviews.length-1] || null;

  return {
    sessionId:       row.id,
    phone:           row.phone,
    name:            row.name || row.phone,
    avatar:          row.avatar || mkAvatar(row.name),
    email:           row.email || '',
    clientId:        row.client_id || '',
    flow:            row.flow || 'cliente',
    status:          row.status,
    unread:          row.unread === 1,
    preview:         row.preview || '',
    startedAt:       row.started_at,
    lastMsgAt:       row.last_message_at,
    agentId:         row.agent_id,
    agentName:       row.agent_name || '',
    agentColor:      row.agent_color || '#00e5a0',
    waName:          row.wa_name || '',
    contactNote:     row.contact_note || '',
    tags:            safeJson(row.tags),
    reviews:         reviews.map(r => ({ id:r.id, quality:r.quality, note:r.note, agentName:r.agent_name, agentColor:r.agent_color, createdAt:r.created_at })),
    lastQuality:     lastRev?.quality || null,
    reviewCount:     reviews.length,
    messages:        msgs.map(m => ({ dir:m.direction, text:m.body, time:m.time_label||'', id:m.meta_id, created_at:m.created_at })),
    sessionHistory:  await Promise.all(history.map(async s => {
      const revs = await all('SELECT * FROM reviews WHERE session_id=$1', [s.id]);
      const cnt  = await get('SELECT COUNT(*) n FROM messages WHERE session_id=$1', [s.id]);
      const last = revs[revs.length-1]||null;
      return { id:s.id, status:s.status, flow:s.flow, startedAt:s.started_at, lastMsgAt:s.last_message_at, preview:s.preview, msgCount:cnt.n, lastQuality:last?.quality||null, reviewCount:revs.length, agentName:s.agent_name, agentColor:s.agent_color, waName:s.wa_name };
    })),
    qualityTimeline: allRevs.map(r => ({ quality:r.quality, note:r.note, agentName:r.agent_name, agentColor:r.agent_color, createdAt:r.created_at })),
  };
}

async function getSessionRows(agentId, from, to) {
  const params = [];
  let where = 'WHERE 1=1';
  if (agentId) { params.push(agentId); where += ` AND s.agent_id=$${params.length}`; }
  if (from)    { params.push(from);    where += ` AND s.last_message_at::date >= $${params.length}::date`; }
  if (to)      { params.push(to);      where += ` AND s.last_message_at::date <= $${params.length}::date`; }
  const res = await pool.query(`
    SELECT s.*,c.name,c.avatar,c.tags,c.contact_note,c.email,c.client_id,
           a.name agent_name,a.color agent_color,w.display_name wa_name
    FROM sessions s
    JOIN contacts c ON c.phone=s.phone
    JOIN agents a ON a.id=s.agent_id
    JOIN wa_accounts w ON w.id=s.wa_account_id
    ${where}
    ORDER BY s.last_message_at DESC
  `, params);
  return res.rows.map(normalizeRow);
}

// ─── Validaciones ─────────────────────────────────────────
const isValidPhone = p => /^\d{7,15}$/.test(p);
const isValidEmail = e => !e || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const isValidAgent = a => !a || ['angel','clara','admin'].includes(a.toLowerCase());

// ─── Log de actividad ────────────────────────────────────
async function logActivity(agentId, username, action, detail='', ip='') {
  try {
    await pool.query(
      'INSERT INTO activity_log (agent_id,username,action,detail,ip) VALUES ($1,$2,$3,$4,$5)',
      [agentId||null, username||'system', action, detail.slice(0,500), ip]
    );
  } catch {}
}

// ─── Auth middleware ──────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Sin token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const jti = decoded.jti || token.slice(-32);
    get('SELECT jti FROM revoked_tokens WHERE jti=$1', [jti]).then(revoked => {
      if (revoked) return res.status(401).json({ error: 'Sesión cerrada. Inicia sesión de nuevo.' });
      req.user = decoded; req.token = token; req.jti = jti;
      next();
    }).catch(() => { req.user = decoded; req.token = token; req.jti = jti; next(); });
  } catch { res.status(401).json({ error: 'Token inválido' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo admins' });
  next();
}

// ─── SSE ─────────────────────────────────────────────────
const clients = new Map();
function broadcastTo(agentId, event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  [String(agentId), 'admin'].forEach(k =>
    clients.get(k)?.forEach(r => { try { r.write(msg); } catch {} })
  );
}

app.get('/events', auth, async (req, res) => {
  res.setHeader('Content-Type',      'text/event-stream');
  res.setHeader('Cache-Control',     'no-cache');
  res.setHeader('Connection',        'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  const key = req.user.role === 'admin' ? 'admin' : String(req.user.id);
  if (!clients.has(key)) clients.set(key, new Set());
  clients.get(key).add(res);
  const agentId = req.user.role === 'admin' ? null : req.user.id;
  const rows = await getSessionRows(agentId, null, null);
  const enriched = await Promise.all(rows.map(enrichSession));
  res.write(`event: init\ndata: ${JSON.stringify(enriched)}\n\n`);
  const ping = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { clearInterval(ping); clients.get(key)?.delete(res); });
});

// ─── Auth ─────────────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  try {
    const { username, password, totp_code } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales' });
    const user = String(username).toLowerCase().trim().slice(0, 64);

    const recentFails = await get(
      `SELECT COUNT(*) n FROM login_attempts WHERE username=$1 AND ip=$2 AND created_at > NOW()-INTERVAL '10 minutes'`,
      [user, ip]
    );
    if (recentFails.n >= 5) {
      console.warn(`🔒 Login bloqueado: ${user} desde ${ip}`);
      return res.status(429).json({ error: 'Cuenta bloqueada temporalmente. Intenta en 10 minutos.' });
    }

    const agent = await get('SELECT * FROM agents WHERE username=$1', [user]);
    if (!agent || !bcrypt.compareSync(password, agent.password)) {
      await pool.query('INSERT INTO login_attempts (username,ip) VALUES ($1,$2)', [user, ip]);
      console.warn(`⚠️  Login fallido: ${user} desde ${ip}`);
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    await pool.query('DELETE FROM login_attempts WHERE username=$1 AND ip=$2', [user, ip]);

    // ── 2FA ──────────────────────────────────────────────
    // Si el agente no tiene 2FA configurado → devolver señal para configurarlo
    if (!agent.totp_enabled || !agent.totp_secret) {
      // Generar secret temporal y devolver QR para configurar
      const secret = speakeasy.generateSecret({
        name: `WA Manager Pro (${agent.username})`,
        issuer: 'WA Manager Pro'
      });
      // Guardar secret temporalmente (no activado aún)
      await pool.query('UPDATE agents SET totp_secret=$1, totp_enabled=FALSE WHERE id=$2',
        [secret.base32, agent.id]);
      const qrUrl = await QRCode.toDataURL(secret.otpauth_url);
      return res.json({
        requires_2fa_setup: true,
        qr: qrUrl,
        secret: secret.base32,
        agent_id: agent.id,
        message: 'Escanea el QR con Google Authenticator y confirma con el código'
      });
    }

    // Si tiene 2FA activado → verificar código
    if (agent.totp_enabled) {
      if (!totp_code) {
        return res.json({ requires_2fa: true, message: 'Introduce el código de Google Authenticator' });
      }
      const valid = speakeasy.totp.verify({
        secret: agent.totp_secret,
        encoding: 'base32',
        token: String(totp_code).replace(/\s/g, ''),
        window: 1
      });
      if (!valid) {
        await pool.query('INSERT INTO login_attempts (username,ip) VALUES ($1,$2)', [user, ip]);
        return res.status(401).json({ error: 'Código 2FA incorrecto' });
      }
    }

    // Login completo ✅
    const jti = `${agent.id}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const token = jwt.sign(
      { id: agent.id, username: agent.username, name: agent.name, role: agent.role, color: agent.color, jti },
      JWT_SECRET, { expiresIn: '8h' }
    );
    await logActivity(agent.id, agent.username, 'login', '', ip);
    res.json({ token, agent: { id: agent.id, username: agent.username, name: agent.name, role: agent.role, color: agent.color } });
  } catch(e) {
    console.error('Login error:', e.message);
    res.status(500).json({ error: IS_TEST ? e.message : 'Error interno del servidor' });
  }
});

app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

// ─── Confirmar configuración 2FA ──────────────────────────
app.post('/api/auth/2fa/confirm', async (req, res) => {
  try {
    const { agent_id, totp_code } = req.body;
    if (!agent_id || !totp_code) return res.status(400).json({ error: 'Faltan datos' });
    const agent = await get('SELECT * FROM agents WHERE id=$1', [+agent_id]);
    if (!agent || !agent.totp_secret) return res.status(400).json({ error: 'No hay secret configurado' });

    const valid = speakeasy.totp.verify({
      secret: agent.totp_secret,
      encoding: 'base32',
      token: String(totp_code).replace(/\s/g, ''),
      window: 1
    });
    if (!valid) return res.status(401).json({ error: 'Código incorrecto. Inténtalo de nuevo.' });

    // Activar 2FA
    await pool.query('UPDATE agents SET totp_enabled=TRUE WHERE id=$1', [+agent_id]);
    console.log(`✅ 2FA activado para agente #${agent_id}`);
    res.json({ ok: true, message: '2FA activado correctamente' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Admin: desactivar 2FA de un agente ──────────────────
app.post('/api/admin/agents/:id/disable-2fa', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('UPDATE agents SET totp_secret=NULL, totp_enabled=FALSE WHERE id=$1', [+req.params.id]);
    await logActivity(req.user.id, req.user.username, 'disable_2fa', `agente #${req.params.id}`, req.ip||'');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/logout', auth, async (req, res) => {
  try {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    await pool.query('INSERT INTO revoked_tokens (jti) VALUES ($1) ON CONFLICT DO NOTHING', [req.jti]);
    await logActivity(req.user.id, req.user.username, 'logout', '', ip);
    await pool.query("DELETE FROM revoked_tokens WHERE revoked_at < NOW()-INTERVAL '9 hours'").catch(()=>{});
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/env', (req, res) => res.json({ env: IS_TEST ? 'test' : 'production' }));

app.get('/api/admin/activity', auth, adminOnly, async (req, res) => {
  try {
    const limit = Math.min(+req.query.limit || 100, 500);
    const logs = await all('SELECT * FROM activity_log ORDER BY id DESC LIMIT $1', [limit]);
    res.json(logs);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Webhook Meta ─────────────────────────────────────────
app.get('/webhook/:vt', async (req, res) => {
  const wa = await get('SELECT * FROM wa_accounts WHERE verify_token=$1', [req.params.vt]);
  if (!wa) return res.sendStatus(404);
  const { 'hub.mode':mode, 'hub.verify_token':token, 'hub.challenge':challenge } = req.query;
  if (mode==='subscribe' && token===wa.verify_token) return res.status(200).send(challenge);
  res.sendStatus(403);
});

app.get('/webhook', async (req, res) => {
  const { 'hub.mode':mode, 'hub.verify_token':token, 'hub.challenge':challenge } = req.query;
  const wa = token ? await get('SELECT * FROM wa_accounts WHERE verify_token=$1', [token]) : null;
  if (wa && mode==='subscribe') return res.status(200).send(challenge);
  res.sendStatus(403);
});

async function processWebhook(body, wa) {
  if (body.object !== 'whatsapp_business_account') return;
  for (const entry of (body.entry||[])) {
    const value = entry.changes?.[0]?.value;
    if (!value?.messages) continue;
    for (const msg of value.messages) {
      try {
        const phone  = msg.from;
        const name   = value.contacts?.find(c=>c.wa_id===phone)?.profile?.name || phone;
        const text   = extractText(msg);
        const time   = nowTime();
        await upsertContact(phone, name);
        const session = await getOrCreateSession(phone, wa.id, wa.agent_id, 'cliente', text);
        await pool.query('INSERT INTO messages (session_id,phone,direction,body,meta_id,time_label) VALUES ($1,$2,$3,$4,$5,$6)',
          [session.id, phone, 'in', text, msg.id, time]);
        const enriched = await buildEnrichedSession(session.id);
        broadcastTo(wa.agent_id, 'message', { sessionId:session.id, phone, conv:enriched });
      } catch(e) { console.error('Webhook msg error:', e.message); }
    }
  }
}

app.post('/webhook/:vt', async (req, res) => {
  res.sendStatus(200);
  const wa = await get('SELECT * FROM wa_accounts WHERE verify_token=$1', [req.params.vt]);
  if (wa) processWebhook(req.body, wa);
});

app.post('/webhook', async (req, res) => {
  res.sendStatus(200);
  const phoneId = req.body?.entry?.[0]?.changes?.[0]?.value?.metadata?.phone_number_id;
  if (phoneId) {
    const wa = await get('SELECT * FROM wa_accounts WHERE phone_number_id=$1', [phoneId]);
    if (wa) processWebhook(req.body, wa);
  }
});

// ─── Helpers de sesión ────────────────────────────────────
async function upsertContact(phone, name, email, clientId) {
  const existing = await get('SELECT * FROM contacts WHERE phone=$1', [phone]);
  if (!existing) {
    await pool.query(
      'INSERT INTO contacts (phone,name,avatar,email,client_id) VALUES ($1,$2,$3,$4,$5)',
      [phone, name||phone, mkAvatar(name||phone), email||'', clientId||'']
    );
  } else {
    if (name && name !== phone && name !== existing.name) {
      await pool.query('UPDATE contacts SET name=$1,avatar=$2 WHERE phone=$3', [name, mkAvatar(name), phone]);
    }
    if (email && !existing.email) {
      await pool.query('UPDATE contacts SET email=$1 WHERE phone=$2', [email, phone]);
    }
    if (clientId && !existing.client_id) {
      await pool.query('UPDATE contacts SET client_id=$1 WHERE phone=$2', [clientId, phone]);
    }
  }
}

async function getOrCreateSession(phone, waId, agentId, flow, preview) {
  const active = await get("SELECT * FROM sessions WHERE phone=$1 AND wa_account_id=$2 AND status='active' ORDER BY id DESC LIMIT 1", [phone, waId]);
  if (active) {
    await pool.query("UPDATE sessions SET preview=$1,unread=1,last_message_at=NOW() WHERE id=$2", [preview, active.id]);
    return await get('SELECT * FROM sessions WHERE id=$1', [active.id]);
  }
  const r = await pool.query(
    'INSERT INTO sessions (phone,wa_account_id,agent_id,flow,preview) VALUES ($1,$2,$3,$4,$5) RETURNING id',
    [phone, waId, agentId, flow||'cliente', preview]
  );
  return await get('SELECT * FROM sessions WHERE id=$1', [r.rows[0].id]);
}

async function buildEnrichedSession(sessionId) {
  const s = await get(`
    SELECT s.*,c.name,c.avatar,c.tags,c.contact_note,c.email,c.client_id,
           a.name agent_name,a.color agent_color,w.display_name wa_name
    FROM sessions s JOIN contacts c ON c.phone=s.phone JOIN agents a ON a.id=s.agent_id JOIN wa_accounts w ON w.id=s.wa_account_id
    WHERE s.id=$1`, [sessionId]);
  return s ? enrichSession(s) : null;
}

// ─── Sesiones ─────────────────────────────────────────────
app.get('/api/sessions', auth, async (req, res) => {
  try {
    const dateRe = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?$/;
    const rawFrom = req.query.from||null, rawTo = req.query.to||null, rawPeriod = req.query.period||null;
    const validPeriods = ['today','week','month','quarter'];
    let dates = {
      from: rawFrom && dateRe.test(rawFrom) ? rawFrom : null,
      to:   rawTo   && dateRe.test(rawTo)   ? rawTo   : null,
    };
    if (rawPeriod && validPeriods.includes(rawPeriod)) { const pd=periodDates(rawPeriod); if(pd) dates=pd; }
    const agentId = req.user.role==='admin' ? null : req.user.id;
    const rows = await getSessionRows(agentId, dates.from, dates.to);
    const enriched = await Promise.all(rows.map(enrichSession));
    res.json(enriched);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sessions/:id', auth, async (req, res) => {
  try {
    const enriched = await buildEnrichedSession(+req.params.id);
    if (!enriched) return res.status(404).json({ error: 'No encontrada' });
    res.json(enriched);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sessions/:id/read', auth, async (req, res) => {
  try { await pool.query('UPDATE sessions SET unread=0 WHERE id=$1', [+req.params.id]); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sessions/:id/review', auth, async (req, res) => {
  try {
    const { quality, note='' } = req.body;
    if (!['alta','media','baja'].includes(quality)) return res.status(400).json({ error: 'quality: alta|media|baja' });
    const id = +req.params.id;
    await pool.query('INSERT INTO reviews (session_id,agent_id,quality,note) VALUES ($1,$2,$3,$4)', [id, req.user.id, quality, note]);
    await pool.query('INSERT INTO messages (session_id,phone,direction,body,time_label) SELECT id,phone,$1,$2,$3 FROM sessions WHERE id=$4',
      ['system', `Revisión · ${quality.toUpperCase()} · ${req.user.name}${note?' · '+note:''}`, nowTime(), id]);
    await logActivity(req.user.id, req.user.username, 'review', `sesión #${id} · ${quality}`, req.ip||'');
    const s = await get('SELECT * FROM sessions WHERE id=$1', [id]);
    const enriched = await buildEnrichedSession(id);
    broadcastTo(s.agent_id, 'review', { sessionId:id, conv:enriched });
    res.json(enriched);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sessions/:id/close', auth, async (req, res) => {
  try {
    const id = +req.params.id;
    await pool.query("UPDATE sessions SET status='closed' WHERE id=$1", [id]);
    await pool.query('INSERT INTO messages (session_id,phone,direction,body,time_label) SELECT id,phone,$1,$2,$3 FROM sessions WHERE id=$4',
      ['system','Sesión cerrada', nowTime(), id]);
    const s = await get('SELECT * FROM sessions WHERE id=$1', [id]);
    const enriched = await buildEnrichedSession(id);
    broadcastTo(s.agent_id, 'sessionClosed', { sessionId:id, conv:enriched });
    res.json(enriched);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Contactos ────────────────────────────────────────────
app.patch('/api/contacts/:phone', auth, async (req, res) => {
  try {
    const { note='', tags=[] } = req.body;
    await pool.query('UPDATE contacts SET contact_note=$1,tags=$2 WHERE phone=$3', [note, JSON.stringify(tags), req.params.phone]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ─── Enviar mensaje ───────────────────────────────────────
app.post('/api/send', auth, async (req, res) => {
  const { phone, text, sessionId } = req.body;
  if (!phone||!text) return res.status(400).json({ error: 'Faltan phone y text' });
  const clean = phone.replace(/[\s+]/g,'');
  try {
    if (EXT_SEND) {
      const r = await fetch(EXT_SEND, {
        method:'POST',
        headers:{ 'Content-Type':'application/json', 'X-Api-Key': EXT_API_KEY },
        body: JSON.stringify({ client_id:clean, phone:'+'+clean.replace(/\D/g,''), message:text, timestamp:new Date().toISOString(), conversation_id:String(sessionId||'') }),
      });
      if (!r.ok) {
        const d = await r.json().catch(()=>({}));
        return res.status(500).json({ error: d.error||'Error sistema externo' });
      }
    } else {
      const wa = await get('SELECT * FROM wa_accounts WHERE agent_id=$1', [req.user.id]);
      if (wa?.wa_token && wa?.phone_number_id) {
        const metaRes = await fetch(`https://graph.facebook.com/v19.0/${wa.phone_number_id}/messages`, {
          method:'POST',
          headers:{ 'Authorization':`Bearer ${wa.wa_token}`, 'Content-Type':'application/json' },
          body: JSON.stringify({ messaging_product:'whatsapp', to:clean, type:'text', text:{ body:text, preview_url:false } }),
        });
        const data = await metaRes.json();
        if (data.error) return res.status(500).json({ error: data.error.message });
      }
    }
    const sid = sessionId || (await get("SELECT id FROM sessions WHERE phone=$1 AND status='active' ORDER BY id DESC LIMIT 1", [clean]))?.id;
    if (sid) {
      await pool.query('INSERT INTO messages (session_id,phone,direction,body,time_label) VALUES ($1,$2,$3,$4,$5)', [sid, clean, 'out', text, nowTime()]);
      await pool.query("UPDATE sessions SET preview=$1,last_message_at=NOW() WHERE id=$2", [text, sid]);
      const enriched = await buildEnrichedSession(sid);
      const s = await get('SELECT agent_id FROM sessions WHERE id=$1', [sid]);
      broadcastTo(s.agent_id, 'message', { sessionId:sid, phone:clean, conv:enriched });
    }
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Integración sistema externo (AWS) ───────────────────
function externalAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== EXT_API_KEY) return res.status(401).json({ error: 'API Key inválida' });
  next();
}

function parseTimestamp(ts) {
  if (!ts) return null;
  const ddmmyyyy = ts.match(/^(\d{2})\/(\d{2})\/(\d{4})(?:[T\s](\d{2}):(\d{2})(?::(\d{2}))?)?/);
  if (ddmmyyyy) {
    const [, dd, mm, yyyy, hh='00', min='00', ss='00'] = ddmmyyyy;
    return new Date(`${yyyy}-${mm}-${dd}T${hh}:${min}:${ss}+01:00`);
  }
  const d = new Date(ts);
  return isNaN(d.getTime()) ? null : d;
}

app.post('/messages/incoming', externalAuth, async (req, res) => {
  try {
    const { client_id, name, phone, email, message, timestamp, conversation_id, direction='incoming', flow='cliente', agent: agentHint } = req.body;
    if (!phone||!message) return res.status(400).json({ error: 'Faltan: phone, message' });

    const clean = phone.replace(/[\s+]/g,'');
    if (!isValidPhone(clean))  return res.status(400).json({ error: 'Formato de teléfono inválido' });
    if (!isValidEmail(email))  return res.status(400).json({ error: 'Formato de email inválido' });
    if (!isValidAgent(agentHint)) return res.status(400).json({ error: 'Agente no válido. Usa: angel, clara' });
    if (String(message).length > 4000) return res.status(400).json({ error: 'Mensaje demasiado largo (máx 4000 chars)' });

    const text  = String(message).trim();
    const parsedTs = parseTimestamp(timestamp);
    const time  = parsedTs ? madridTime(parsedTs).toISOString().slice(11,16) : nowTime();
    const dir   = direction==='incoming' ? 'in' : 'bot';

    await upsertContact(clean, name, email, client_id);

    let wa = null, agentId = null;
    if (agentHint) {
      const ag = await get('SELECT id FROM agents WHERE username=$1', [agentHint.toLowerCase()]);
      if (ag) { wa = await get('SELECT * FROM wa_accounts WHERE agent_id=$1', [ag.id]); agentId = ag.id; }
    }
    if (!wa) {
      const existSess = await get("SELECT s.*,s.wa_account_id wa_id FROM sessions s WHERE s.phone=$1 AND s.status='active' ORDER BY s.id DESC LIMIT 1", [clean]);
      if (existSess) { wa = await get('SELECT * FROM wa_accounts WHERE id=$1', [existSess.wa_id]); agentId = existSess.agent_id; }
    }
    if (!wa) {
      wa = await get('SELECT * FROM wa_accounts LIMIT 1');
      if (wa) agentId = wa.agent_id;
    }
    if (!wa||!agentId) return res.status(500).json({ error: 'No hay cuentas WA configuradas' });

    const session = await getOrCreateSession(clean, wa.id, agentId, flow, text);
    await pool.query('INSERT INTO messages (session_id,phone,direction,body,meta_id,time_label) VALUES ($1,$2,$3,$4,$5,$6)',
      [session.id, clean, dir, text, conversation_id||null, time]);

    const enriched = await buildEnrichedSession(session.id);
    broadcastTo(agentId, 'message', { sessionId:session.id, phone:clean, conv:enriched });
    console.log(`📥 [AWS/${direction}] ${name||clean}: ${text.slice(0,60)}`);
    res.json({ ok:true, session_id:session.id });
  } catch(e) { console.error('/messages/incoming:', e.message); res.status(500).json({ error: e.message }); }
});

app.post('/messages/outgoing', externalAuth, async (req, res) => {
  try {
    const { phone, message, timestamp, conversation_id } = req.body;
    if (!message) return res.status(400).json({ error: 'Falta message' });
    const clean = phone ? phone.replace(/[\s+]/g,'') : null;
    const text  = String(message).trim();
    const parsedTs = parseTimestamp(timestamp);
    const time  = parsedTs ? madridTime(parsedTs).toISOString().slice(11,16) : nowTime();

    if (clean) {
      const session = await get("SELECT * FROM sessions WHERE phone=$1 AND status='active' ORDER BY id DESC LIMIT 1", [clean]);
      if (session) {
        await pool.query('INSERT INTO messages (session_id,phone,direction,body,meta_id,time_label) VALUES ($1,$2,$3,$4,$5,$6)',
          [session.id, clean, 'out', text, conversation_id||null, time]);
        await pool.query("UPDATE sessions SET preview=$1,last_message_at=NOW() WHERE id=$2", [text, session.id]);
        const enriched = await buildEnrichedSession(session.id);
        broadcastTo(session.agent_id, 'message', { sessionId:session.id, phone:clean, conv:enriched });
      }
    }
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Analítica ────────────────────────────────────────────
app.get('/api/analytics', auth, async (req, res) => {
  try {
    const aid = req.user.role==='admin' ? (req.query.agent_id?+req.query.agent_id:null) : req.user.id;
    const dateRe = /^\d{4}-\d{2}-\d{2}$/;
    const validPeriods = ['today','week','month','quarter'];
    let dates = {
      from: req.query.from && dateRe.test(req.query.from) ? req.query.from : null,
      to:   req.query.to   && dateRe.test(req.query.to)   ? req.query.to   : null,
    };
    if (req.query.period && validPeriods.includes(req.query.period)) {
      const pd = periodDates(req.query.period); if (pd) dates = pd;
    }

    // Construir cláusulas SQL con parámetros posicionales independientes
    function buildClauses(useReviewDate) {
      const p = [];
      const next = () => { return `$${p.length}`; };
      let ac='', fc='', tc='', rac='', rc='', rt='';
      if (aid)        { p.push(aid);        if (!useReviewDate) ac  = `AND s.agent_id=${next()}`; else rac = `AND s.agent_id=${next()}`; }
      if (dates.from) { p.push(dates.from); if (!useReviewDate) fc  = `AND s.started_at::date >= ${next()}::date`; else rc = `AND r.created_at::date >= ${next()}::date`; }
      if (dates.to)   { p.push(dates.to);   if (!useReviewDate) tc  = `AND s.started_at::date <= ${next()}::date`; else rt = `AND r.created_at::date <= ${next()}::date`; }
      return { params: p, ac, fc, tc, rac, rc, rt };
    }

    const s = buildClauses(false);
    const r = buildClauses(true);

    const q = (sql, params) => pool.query(sql, params).then(res => res.rows.map(normalizeRow));
    const q1 = (sql, params) => pool.query(sql, params).then(res => normalizeRow(res.rows[0] || {}));

    const [summary, byQrows, agentRows, sessDay, revDay, topC, noReply] = await Promise.all([
      q1(`SELECT COUNT(DISTINCT s.id) total_sessions, COUNT(DISTINCT CASE WHEN s.status='active' THEN s.id END) active_sessions, COUNT(DISTINCT CASE WHEN s.unread=1 AND s.status='active' THEN s.id END) unread, COUNT(DISTINCT c.phone) total_contacts, COUNT(r.id) total_reviews FROM sessions s JOIN contacts c ON c.phone=s.phone LEFT JOIN reviews r ON r.session_id=s.id WHERE 1=1 ${s.ac} ${s.fc} ${s.tc}`, s.params),
      q(`SELECT r.quality, COUNT(*) n FROM reviews r JOIN sessions s ON s.id=r.session_id WHERE 1=1 ${r.rac} ${r.rc} ${r.rt} GROUP BY r.quality`, r.params),
      q(`SELECT a.name, a.color, r.quality, COUNT(*) n FROM reviews r JOIN agents a ON a.id=r.agent_id JOIN sessions s ON s.id=r.session_id WHERE a.role='agent' ${r.rac} ${r.rc} ${r.rt} GROUP BY a.name,a.color,r.quality`, r.params),
      q(`SELECT s.started_at::date AS day, COUNT(*) n FROM sessions s WHERE 1=1 ${s.ac} ${s.fc} ${s.tc} GROUP BY s.started_at::date ORDER BY s.started_at::date`, s.params),
      q(`SELECT r.created_at::date AS day, r.quality, COUNT(*) n FROM reviews r JOIN sessions s ON s.id=r.session_id WHERE 1=1 ${r.rac} ${r.rc} ${r.rt} GROUP BY r.created_at::date,r.quality ORDER BY r.created_at::date`, r.params),
      q(`SELECT c.phone,c.name,COUNT(DISTINCT s.id) sessions FROM contacts c JOIN sessions s ON s.phone=c.phone WHERE 1=1 ${s.ac} ${s.fc} ${s.tc} GROUP BY c.phone,c.name ORDER BY sessions DESC LIMIT 10`, s.params),
      q(`SELECT s.id session_id,s.phone,c.name,c.avatar,a.name agent_name,a.color agent_color,w.display_name wa_name,lm.body last_body,lm.created_at last_msg_at,FLOOR(EXTRACT(EPOCH FROM (NOW()-lm.created_at))/86400) days_waiting FROM sessions s JOIN contacts c ON c.phone=s.phone JOIN agents a ON a.id=s.agent_id JOIN wa_accounts w ON w.id=s.wa_account_id JOIN messages lm ON lm.id=(SELECT id FROM messages WHERE session_id=s.id AND direction IN ('out','bot') ORDER BY id DESC LIMIT 1) WHERE s.status='active' ${s.ac} AND NOT EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction='in' AND created_at>lm.created_at) AND EXTRACT(EPOCH FROM (NOW()-lm.created_at))/86400>3 ORDER BY days_waiting DESC`, s.params),
    ]);

    // Tasa de respuesta: semana anterior y mes anterior
    const now = new Date();
    const dayOfWeek = now.getUTCDay() || 7;
    const prevMonday = new Date(now); prevMonday.setUTCDate(now.getUTCDate() - dayOfWeek - 6);
    const prevSunday = new Date(now); prevSunday.setUTCDate(now.getUTCDate() - dayOfWeek);
    const wDates = { from: prevMonday.toISOString().slice(0,10), to: prevSunday.toISOString().slice(0,10) };
    const prevMonth = new Date(now.getUTCFullYear(), now.getUTCMonth() - 1, 1);
    const prevMonthEnd = new Date(now.getUTCFullYear(), now.getUTCMonth(), 0);
    const mDates = { from: prevMonth.toISOString().slice(0,10), to: prevMonthEnd.toISOString().slice(0,10) };

    const wParams = aid ? [aid] : [];
    const wAc = aid ? 's.agent_id=$1 AND' : '1=1 AND';

    const [repliedW, notRepliedW, repliedM, notRepliedM] = await Promise.all([
      q1(`SELECT COUNT(DISTINCT s.id) n FROM sessions s WHERE ${wAc} s.started_at::date >= '${wDates.from}' AND s.started_at::date <= '${wDates.to}' AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) AND EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot')))`, wParams),
      q1(`SELECT COUNT(DISTINCT s.id) n FROM sessions s WHERE ${wAc} s.started_at::date >= '${wDates.from}' AND s.started_at::date <= '${wDates.to}' AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) AND NOT EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot'))) AND EXTRACT(EPOCH FROM (NOW()-s.last_message_at))/86400>3`, wParams),
      q1(`SELECT COUNT(DISTINCT s.id) n FROM sessions s WHERE ${wAc} s.started_at::date >= '${mDates.from}' AND s.started_at::date <= '${mDates.to}' AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) AND EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot')))`, wParams),
      q1(`SELECT COUNT(DISTINCT s.id) n FROM sessions s WHERE ${wAc} s.started_at::date >= '${mDates.from}' AND s.started_at::date <= '${mDates.to}' AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) AND NOT EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot'))) AND EXTRACT(EPOCH FROM (NOW()-s.last_message_at))/86400>3`, wParams),
    ]);

    const [weeklyRate, monthlyRate] = await Promise.all([
      q(`SELECT TO_CHAR(s.started_at, 'IYYY-IW') week,COUNT(DISTINCT s.id) total,COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot'))) THEN s.id END) replied FROM sessions s WHERE s.started_at>=NOW()-INTERVAL '90 days' ${s.ac} AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) GROUP BY week ORDER BY week ASC`, s.params),
      q(`SELECT TO_CHAR(s.started_at, 'YYYY-MM') month,COUNT(DISTINCT s.id) total,COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot'))) THEN s.id END) replied FROM sessions s WHERE s.started_at>=NOW()-INTERVAL '365 days' ${s.ac} AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) GROUP BY month ORDER BY month ASC`, s.params),
    ]);

    const dayMap = {};
    revDay.forEach(row => { const d=String(row.day).slice(0,10); if(!dayMap[d]) dayMap[d]={alta:0,media:0,baja:0}; dayMap[d][row.quality]=+row.n; });
    sessDay.forEach(row => { const d=String(row.day).slice(0,10); if(!dayMap[d]) dayMap[d]={alta:0,media:0,baja:0}; dayMap[d].total=+row.n; });
    const byAgent = {};
    agentRows.forEach(row => { if(!byAgent[row.name]) byAgent[row.name]={color:row.color,alta:0,media:0,baja:0}; byAgent[row.name][row.quality]=+row.n; });

    const thisMonth = await q1(`SELECT COUNT(*) n FROM sessions WHERE TO_CHAR(started_at,'YYYY-MM')=TO_CHAR(NOW(),'YYYY-MM') ${s.ac}`, s.params);

    res.json({
      period: dates,
      summary: { ...summary, thisMonth: +thisMonth.n },
      byQuality: Object.fromEntries(byQrows.map(row=>[row.quality,+row.n])),
      byAgent,
      qualityPerDay: Object.entries(dayMap).sort(([a],[b])=>a.localeCompare(b)).map(([day,v])=>({day,...v})),
      topContacts: topC,
      agents: req.user.role==='admin' ? (await pool.query('SELECT id,username,name,role,color FROM agents')).rows : [],
      noReply: noReply.map(row=>({ sessionId:row.session_id, phone:row.phone, name:row.name, avatar:row.avatar, agentName:row.agent_name, agentColor:row.agent_color, waName:row.wa_name, lastBody:row.last_body, lastMsgAt:row.last_msg_at, daysWaiting:row.days_waiting })),
      responseRate: {
        week:  { from:wDates.from, to:wDates.to, replied:+repliedW.n||0, notReplied:+notRepliedW.n||0, total:(+repliedW.n||0)+(+notRepliedW.n||0) },
        month: { from:mDates.from, to:mDates.to, replied:+repliedM.n||0, notReplied:+notRepliedM.n||0, total:(+repliedM.n||0)+(+notRepliedM.n||0) },
      },
      weeklyRate:  weeklyRate.map(row=>({ period:row.week,  total:+row.total, replied:+row.replied, notReplied:(+row.total)-(+row.replied) })),
      monthlyRate: monthlyRate.map(row=>({ period:row.month, total:+row.total, replied:+row.replied, notReplied:(+row.total)-(+row.replied) })),
    });
  } catch(e) { console.error('/api/analytics:', e.message); res.status(500).json({ error: e.message }); }
});


// ─── Admin ────────────────────────────────────────────────
app.get('/api/admin/agents', auth, adminOnly, async (req,res) => res.json(await all('SELECT id,username,name,role,color,totp_enabled FROM agents')));
app.get('/api/admin/wa-accounts', auth, adminOnly, async (req,res) => res.json(await all('SELECT w.*,a.name agent_name,a.color agent_color FROM wa_accounts w JOIN agents a ON a.id=w.agent_id')));

app.patch('/api/admin/wa-accounts/:id', auth, adminOnly, async (req, res) => {
  try {
    const { phone_number_id, wa_token, verify_token, display_name } = req.body;
    await pool.query('UPDATE wa_accounts SET phone_number_id=COALESCE($1,phone_number_id),wa_token=COALESCE($2,wa_token),verify_token=COALESCE($3,verify_token),display_name=COALESCE($4,display_name) WHERE id=$5',
      [phone_number_id||null, wa_token||null, verify_token||null, display_name||null, +req.params.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.patch('/api/admin/agents/:id/password', auth, adminOnly, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password||password.length<6) return res.status(400).json({ error:'Mínimo 6 caracteres' });
    await pool.query('UPDATE agents SET password=$1 WHERE id=$2', [bcrypt.hashSync(password,10), +req.params.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/admin/reset', auth, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM messages');
    await pool.query('DELETE FROM reviews');
    await pool.query('DELETE FROM sessions');
    await pool.query('DELETE FROM contacts');
    await pool.query('DELETE FROM login_attempts');
    console.log(`🗑️  BD reseteada por ${req.user.username}`);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ─── Seed demo — solo en TEST ─────────────────────────────
app.post('/api/demo/seed', async (req, res) => {
  if (!IS_TEST) return res.status(403).json({ error: 'No disponible en producción' });
  try {
    const angel = await get('SELECT id FROM agents WHERE username=$1',['angel']);
    const clara = await get('SELECT id FROM agents WHERE username=$1',['clara']);
    const waA   = await get('SELECT * FROM wa_accounts WHERE agent_id=$1',[angel.id]);
    const waC   = await get('SELECT * FROM wa_accounts WHERE agent_id=$1',[clara.id]);

    const contacts = [['34612345678','María García','MG'],['34634567890','Carlos López','CL'],['34698123456','Ana Martínez','AM'],['34677890234','Pedro Sánchez','PS'],['34655432109','Laura Fernández','LF'],['34698765432','Javier Moreno','JM']];
    for (const [p,n,av] of contacts) {
      await pool.query('INSERT INTO contacts (phone,name,avatar) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',[p,n,av]);
    }

    const hist = [
      {phone:'34612345678',wa:waA,ag:angel,flow:'cliente',days:14,msgs:[['in','Quiero el X300'],['out','Claro'],['in','Lo compro']],revs:[{q:'alta',note:'Compra cerrada'}]},
      {phone:'34634567890',wa:waA,ag:angel,flow:'crm',    days:20,msgs:[['bot','[CRM] #3210'],['in','Gracias']],revs:[{q:'alta',note:'VIP'}]},
      {phone:'34698123456',wa:waC,ag:clara,flow:'mkt',    days:12,msgs:[['bot','[Mkt] Oferta'],['in','k']],revs:[{q:'baja',note:'Sin interés'}]},
    ];

    for (const s of hist) {
      const d = new Date(); d.setDate(d.getDate()-s.days);
      const start = new Date(d); start.setHours(9,0,0,0);
      const end   = new Date(start); end.setHours(10,30,0,0);
      const r = await pool.query(
        'INSERT INTO sessions (phone,wa_account_id,agent_id,flow,status,preview,started_at,last_message_at,unread) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
        [s.phone,s.wa.id,s.ag.id,s.flow,'closed',s.msgs[s.msgs.length-1][1],start.toISOString(),end.toISOString(),0]
      );
      const sid = r.rows[0].id;
      for (let i=0;i<s.msgs.length;i++) {
        const t=new Date(start);t.setMinutes(t.getMinutes()+i*5);
        await pool.query('INSERT INTO messages (session_id,phone,direction,body,time_label) VALUES ($1,$2,$3,$4,$5)',[sid,s.phone,s.msgs[i][0],s.msgs[i][1],madridTime(t).toISOString().slice(11,16)]);
      }
      for (let i=0;i<s.revs.length;i++) {
        const t=new Date(end);t.setMinutes(t.getMinutes()+i*10);
        await pool.query('INSERT INTO reviews (session_id,agent_id,quality,note,created_at) VALUES ($1,$2,$3,$4,$5)',[sid,s.ag.id,s.revs[i].q,s.revs[i].note,t.toISOString()]);
        await pool.query('INSERT INTO messages (session_id,phone,direction,body,time_label) VALUES ($1,$2,$3,$4,$5)',[sid,s.phone,'system',`Revisión · ${s.revs[i].q.toUpperCase()}${s.revs[i].note?' · '+s.revs[i].note:''}`,madridTime(t).toISOString().slice(11,16)]);
      }
    }

    const active = [
      {phone:'34612345678',wa:waA,ag:angel,flow:'cliente',msgs:[['in','¿Stock del X300?']]},
      {phone:'34698123456',wa:waC,ag:clara,flow:'mkt',    msgs:[['bot','[Mkt] Primavera'],['in','¿Cuánto?']]},
    ];
    for (const s of active) {
      const ex = await get("SELECT id FROM sessions WHERE phone=$1 AND wa_account_id=$2 AND status='active'",[s.phone,s.wa.id]);
      if (ex) continue;
      const r = await pool.query('INSERT INTO sessions (phone,wa_account_id,agent_id,flow,preview) VALUES ($1,$2,$3,$4,$5) RETURNING id',[s.phone,s.wa.id,s.ag.id,s.flow,s.msgs[s.msgs.length-1][1]]);
      const sid = r.rows[0].id;
      for (let i=0;i<s.msgs.length;i++) await pool.query('INSERT INTO messages (session_id,phone,direction,body,time_label) VALUES ($1,$2,$3,$4,$5)',[sid,s.phone,s.msgs[i][0],s.msgs[i][1],`${9+i}:0${i}`]);
    }

    res.json({ ok:true, logins:{ admin:'admin123', angel:'angel123', clara:'clara123' } });
  } catch(e) { console.error('Seed error:',e); res.status(500).json({ error:e.message }); }
});

// ─── Manejador global de errores ─────────────────────────
app.use((err, req, res, next) => {
  console.error('Error no controlado:', err.message);
  res.status(500).json({ error: IS_TEST ? err.message : 'Error interno del servidor' });
});

// ─── Arrancar ─────────────────────────────────────────────
initDB().then(async () => {
  app.listen(PORT, async () => {
    console.log(`
╔══════════════════════════════════════════════════════╗
║  ${IS_TEST ? '🟡  WA Manager Pro  [ENTORNO TEST]' : '🟢  WA Manager Pro  →  PRODUCCIÓN    '}  :${PORT}  ║
╠══════════════════════════════════════════════════════╣
║  DB: PostgreSQL                                      ║
║  Sistema externo (AWS):                              ║
║    POST /messages/incoming  (header X-Api-Key)       ║
║    POST /messages/outgoing  (header X-Api-Key)       ║${IS_TEST ? `
║  ⚠️  TEST: seed demo auto, contraseñas por defecto   ║` : ''}
╚══════════════════════════════════════════════════════╝`);

    if (IS_TEST) {
      const count = await get('SELECT COUNT(*) n FROM sessions').catch(() => ({ n: 0 }));
      if (+count.n === 0) {
        console.log('🌱 TEST: ejecutando seed de demo automático...');
        await fetch(`http://localhost:${PORT}/api/demo/seed`, { method: 'POST' })
          .then(() => console.log('✅ Seed demo completado'))
          .catch(e => console.warn('⚠️  Seed demo falló:', e.message));
      }
    }
  });
}).catch(e => { console.error('Error iniciando DB:', e); process.exit(1); });
