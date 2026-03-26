// v2 - fix hora Madrid
/**
 * WA Manager Pro — server.js
 * ═══════════════════════════════════════════════════════
 * Base de datos : sqlite3 (binarios precompilados, no necesita compilar)
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
const sqlite3      = require('sqlite3').verbose();
const fs           = require('fs');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');

const app = express();

// ─── Cabeceras de seguridad HTTP (Helmet) ─────────────────
// CSP desactivado — el HTML usa eventos inline (onclick, onkeydown) y CDN externos
// El resto de protecciones de Helmet siguen activas (X-Frame-Options, HSTS, etc.)
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false, // Necesario para SSE
}));

// ─── CORS restringido ─────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // Permitir sin origin (Railway health checks, mismo dominio)
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
// Login: máximo 10 intentos por IP cada 15 minutos
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Demasiados intentos. Espera 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// API general: máximo 200 peticiones por IP cada 1 minuto
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  message: { error: 'Demasiadas peticiones. Intenta en unos segundos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Webhooks externos: máximo 300 por minuto
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  message: { error: 'Rate limit excedido en webhook.' },
});

app.use('/api/', apiLimiter);
app.use('/messages/', webhookLimiter);
app.use('/webhook', webhookLimiter);

// ─── Entorno ──────────────────────────────────────────────
const IS_TEST = (process.env.NODE_ENV || 'production') === 'test';

if (IS_TEST) {
  console.log('⚠️  Arrancando en modo TEST — datos de prueba, no usar en producción');
} else {
  // En producción, variables críticas son obligatorias
  const required = ['JWT_SECRET', 'EXTERNAL_API_KEY'];
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

// ─── Base de datos ────────────────────────────────────────
const dbDir  = path.join(__dirname, 'db');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
const dbFile = IS_TEST ? 'wa_test.db' : 'wa.db';
const db = new sqlite3.Database(path.join(dbDir, dbFile));

// Wrapper para usar promesas con sqlite3
const run  = (sql, p=[]) => new Promise((res,rej) => db.run(sql,p, function(e){ e?rej(e):res(this); }));
const get  = (sql, p=[]) => new Promise((res,rej) => db.get(sql,p,(e,r)=> e?rej(e):res(r)));
const all  = (sql, p=[]) => new Promise((res,rej) => db.all(sql,p,(e,r)=> e?rej(e):res(r)));

// ─── Inicializar tablas ───────────────────────────────────
async function initDB() {
  await run('PRAGMA foreign_keys = ON');
  await run(`CREATE TABLE IF NOT EXISTS agents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    name       TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'agent',
    color      TEXT DEFAULT '#00e5a0',
    password   TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  await run(`CREATE TABLE IF NOT EXISTS wa_accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id        INTEGER NOT NULL REFERENCES agents(id),
    display_name    TEXT NOT NULL,
    phone_number_id TEXT NOT NULL DEFAULT '',
    wa_token        TEXT NOT NULL DEFAULT '',
    verify_token    TEXT NOT NULL DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now'))
  )`);
  await run(`CREATE TABLE IF NOT EXISTS contacts (
    phone        TEXT PRIMARY KEY,
    name         TEXT NOT NULL DEFAULT 'Desconocido',
    avatar       TEXT DEFAULT '??',
    email        TEXT DEFAULT '',
    client_id    TEXT DEFAULT '',
    contact_note TEXT DEFAULT '',
    tags         TEXT DEFAULT '[]',
    created_at   TEXT DEFAULT (datetime('now'))
  )`);
  await run(`CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    phone           TEXT NOT NULL,
    wa_account_id   INTEGER NOT NULL,
    agent_id        INTEGER NOT NULL,
    flow            TEXT DEFAULT 'cliente',
    status          TEXT DEFAULT 'active',
    unread          INTEGER DEFAULT 1,
    preview         TEXT DEFAULT '',
    started_at      TEXT DEFAULT (datetime('now')),
    last_message_at TEXT DEFAULT (datetime('now'))
  )`);
  await run(`CREATE TABLE IF NOT EXISTS reviews (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    agent_id   INTEGER NOT NULL,
    quality    TEXT NOT NULL,
    note       TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  await run(`CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    phone      TEXT NOT NULL,
    direction  TEXT NOT NULL,
    body       TEXT NOT NULL,
    meta_id    TEXT,
    time_label TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  // Tabla para rastrear intentos de login fallidos
  await run(`CREATE TABLE IF NOT EXISTS login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL,
    ip         TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  // Índices
  for (const idx of [
    'CREATE INDEX IF NOT EXISTS idx_sess_phone  ON sessions(phone)',
    'CREATE INDEX IF NOT EXISTS idx_sess_agent  ON sessions(agent_id)',
    'CREATE INDEX IF NOT EXISTS idx_sess_status ON sessions(status)',
    'CREATE INDEX IF NOT EXISTS idx_msg_sess    ON messages(session_id)',
    'CREATE INDEX IF NOT EXISTS idx_rev_sess    ON reviews(session_id)',
  ]) await run(idx);

  console.log('✅ Base de datos lista');
  // Migraciones: añadir columnas si no existen
  await run("ALTER TABLE contacts ADD COLUMN email TEXT DEFAULT ''").catch(() => {});
  await run("ALTER TABLE contacts ADD COLUMN client_id TEXT DEFAULT ''").catch(() => {});
  await seedAgents();
}

// ─── Crear agentes iniciales ──────────────────────────────
async function seedAgents() {
  const agentsList = [
    { u:'admin', n:'Administrador', r:'admin',  c:'#a78bfa', p: process.env.ADMIN_PASSWORD || 'admin123'  },
    { u:'angel', n:'Ángel',          r:'agent',  c:'#00e5a0', p: process.env.ANGEL_PASSWORD || 'angel123'  },
    { u:'clara', n:'Clara',           r:'agent',  c:'#f5a623', p: process.env.CLARA_PASSWORD || 'clara123'  },
  ];
  for (const a of agentsList) {
    const existing = await get('SELECT id FROM agents WHERE username=?', [a.u]);
    if (!existing) {
      await run('INSERT INTO agents (username,name,role,color,password) VALUES (?,?,?,?,?)',
        [a.u, a.n, a.r, a.c, bcrypt.hashSync(a.p, 10)]);
      console.log(`✅ ${a.n} creado`);
    }
  }
  // Crear cuentas WA placeholder si no existen
  const angel = await get('SELECT id FROM agents WHERE username=?', ['angel']);
  const clara = await get('SELECT id FROM agents WHERE username=?', ['clara']);
  for (const [agId, name, phoneId, token, verify] of [
    [angel.id, 'WhatsApp Ángel',
      process.env.ANGEL_PHONE_NUMBER_ID || '',
      process.env.ANGEL_WA_TOKEN        || '',
      process.env.ANGEL_VERIFY_TOKEN    || 'verify_angel'],
    [clara.id, 'WhatsApp Clara',
      process.env.CLARA_PHONE_NUMBER_ID || '',
      process.env.CLARA_WA_TOKEN        || '',
      process.env.CLARA_VERIFY_TOKEN    || 'verify_clara'],
  ]) {
    const ex = await get('SELECT id FROM wa_accounts WHERE agent_id=?', [agId]);
    if (!ex) {
      await run('INSERT INTO wa_accounts (agent_id,display_name,phone_number_id,wa_token,verify_token) VALUES (?,?,?,?,?)',
        [agId, name, phoneId, token, verify]);
    }
  }
}

// ─── Helpers ─────────────────────────────────────────────
// Hora de Madrid con cambio automático verano/invierno
function madridTime(date) {
  const d = date || new Date();
  // Detectar si estamos en horario de verano (último domingo de marzo a último domingo de octubre)
  const year = d.getUTCFullYear();
  // Último domingo de marzo
  const lastSundayMarch = new Date(Date.UTC(year, 2, 31));
  lastSundayMarch.setUTCDate(31 - lastSundayMarch.getUTCDay());
  // Último domingo de octubre
  const lastSundayOctober = new Date(Date.UTC(year, 9, 31));
  lastSundayOctober.setUTCDate(31 - lastSundayOctober.getUTCDay());
  // En horario de verano sumamos 2h, en invierno 1h
  const isSummer = d >= lastSundayMarch && d < lastSundayOctober;
  const offset = isSummer ? 2 : 1;
  const local = new Date(d.getTime() + offset * 3600000);
  return local;
}
const nowTime = () => {
  const d = madridTime();
  return d.toISOString().slice(11,16).replace(':', ':');
};
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
  const msgs    = await all('SELECT * FROM messages WHERE session_id=? ORDER BY id ASC', [row.id]);
  const reviews = await all('SELECT r.*,a.name agent_name,a.color agent_color FROM reviews r JOIN agents a ON a.id=r.agent_id WHERE r.session_id=? ORDER BY r.id ASC', [row.id]);
  const history = await all('SELECT s.*,a.name agent_name,a.color agent_color,w.display_name wa_name FROM sessions s JOIN agents a ON a.id=s.agent_id JOIN wa_accounts w ON w.id=s.wa_account_id WHERE s.phone=? AND s.id!=? ORDER BY s.id DESC', [row.phone, row.id]);
  const allRevs = await all('SELECT r.*,a.name agent_name,a.color agent_color FROM reviews r JOIN agents a ON a.id=r.agent_id WHERE r.session_id IN (SELECT id FROM sessions WHERE phone=?) ORDER BY r.created_at DESC', [row.phone]);
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
      const revs = await all('SELECT * FROM reviews WHERE session_id=?', [s.id]);
      const cnt  = await get('SELECT COUNT(*) n FROM messages WHERE session_id=?', [s.id]);
      const last = revs[revs.length-1]||null;
      return { id:s.id, status:s.status, flow:s.flow, startedAt:s.started_at, lastMsgAt:s.last_message_at, preview:s.preview, msgCount:cnt.n, lastQuality:last?.quality||null, reviewCount:revs.length, agentName:s.agent_name, agentColor:s.agent_color, waName:s.wa_name };
    })),
    qualityTimeline: allRevs.map(r => ({ quality:r.quality, note:r.note, agentName:r.agent_name, agentColor:r.agent_color, createdAt:r.created_at })),
  };
}

async function getSessionRows(agentId, from, to) {
  const fromClause = from ? `AND date(s.last_message_at) >= '${from}'` : '';
  const toClause   = to   ? `AND date(s.last_message_at) <= '${to}'`   : '';
  const agentClause= agentId ? `AND s.agent_id=${agentId}` : '';
  return all(`
    SELECT s.*,c.name,c.avatar,c.tags,c.contact_note,c.email,c.client_id,
           a.name agent_name,a.color agent_color,w.display_name wa_name
    FROM sessions s
    JOIN contacts c ON c.phone=s.phone
    JOIN agents a ON a.id=s.agent_id
    JOIN wa_accounts w ON w.id=s.wa_account_id
    WHERE 1=1 ${agentClause} ${fromClause} ${toClause}
    ORDER BY s.last_message_at DESC
  `);
}

// ─── Auth middleware ──────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Sin token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido' }); }
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
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales' });

    const user = String(username).toLowerCase().trim().slice(0, 64);

    // Bloqueo por intentos fallidos: máx 5 en 10 minutos por username+IP
    const recentFails = await get(
      `SELECT COUNT(*) n FROM login_attempts WHERE username=? AND ip=? AND created_at > datetime('now','-10 minutes')`,
      [user, ip]
    );
    if (recentFails.n >= 5) {
      console.warn(`🔒 Login bloqueado: ${user} desde ${ip} (${recentFails.n} intentos)`);
      return res.status(429).json({ error: 'Cuenta bloqueada temporalmente. Intenta en 10 minutos.' });
    }

    const agent = await get('SELECT * FROM agents WHERE username=?', [user]);
    if (!agent || !bcrypt.compareSync(password, agent.password)) {
      // Registrar intento fallido
      await run('INSERT INTO login_attempts (username,ip) VALUES (?,?)', [user, ip]);
      console.warn(`⚠️  Login fallido: ${user} desde ${ip}`);
      // Mismo mensaje para usuario no encontrado o contraseña incorrecta (no revelar cuál)
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    // Login exitoso — limpiar intentos fallidos
    await run('DELETE FROM login_attempts WHERE username=? AND ip=?', [user, ip]);

    const token = jwt.sign(
      { id: agent.id, username: agent.username, name: agent.name, role: agent.role, color: agent.color },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, agent: { id: agent.id, username: agent.username, name: agent.name, role: agent.role, color: agent.color } });
  } catch(e) {
    console.error('Login error:', e.message);
    res.status(500).json({ error: IS_TEST ? e.message : 'Error interno del servidor' });
  }
});

app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

// ─── Info de entorno (público, para el frontend) ──────────
app.get('/api/env', (req, res) => res.json({ env: IS_TEST ? 'test' : 'production' }));

// ─── Webhook Meta ─────────────────────────────────────────
app.get('/webhook/:vt', async (req, res) => {
  const wa = await get('SELECT * FROM wa_accounts WHERE verify_token=?', [req.params.vt]);
  if (!wa) return res.sendStatus(404);
  const { 'hub.mode':mode, 'hub.verify_token':token, 'hub.challenge':challenge } = req.query;
  if (mode==='subscribe' && token===wa.verify_token) return res.status(200).send(challenge);
  res.sendStatus(403);
});

app.get('/webhook', async (req, res) => {
  const { 'hub.mode':mode, 'hub.verify_token':token, 'hub.challenge':challenge } = req.query;
  const wa = token ? await get('SELECT * FROM wa_accounts WHERE verify_token=?', [token]) : null;
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
        await run('INSERT INTO messages (session_id,phone,direction,body,meta_id,time_label) VALUES (?,?,?,?,?,?)',
          [session.id, phone, 'in', text, msg.id, time]);
        const enriched = await buildEnrichedSession(session.id);
        broadcastTo(wa.agent_id, 'message', { sessionId:session.id, phone, conv:enriched });
      } catch(e) { console.error('Webhook msg error:', e.message); }
    }
  }
}

app.post('/webhook/:vt', async (req, res) => {
  res.sendStatus(200);
  const wa = await get('SELECT * FROM wa_accounts WHERE verify_token=?', [req.params.vt]);
  if (wa) processWebhook(req.body, wa);
});

app.post('/webhook', async (req, res) => {
  res.sendStatus(200);
  const phoneId = req.body?.entry?.[0]?.changes?.[0]?.value?.metadata?.phone_number_id;
  if (phoneId) {
    const wa = await get('SELECT * FROM wa_accounts WHERE phone_number_id=?', [phoneId]);
    if (wa) processWebhook(req.body, wa);
  }
});

// ─── Helpers de sesión ────────────────────────────────────
async function upsertContact(phone, name, email, clientId) {
  const existing = await get('SELECT * FROM contacts WHERE phone=?', [phone]);
  if (!existing) {
    await run('INSERT INTO contacts (phone,name,avatar,email,client_id) VALUES (?,?,?,?,?)',
      [phone, name||phone, mkAvatar(name||phone), email||'', clientId||'']);
  } else {
    if (name && name !== phone && name !== existing.name) {
      await run('UPDATE contacts SET name=?,avatar=? WHERE phone=?', [name, mkAvatar(name), phone]);
    }
    if (email && !existing.email) {
      await run('UPDATE contacts SET email=? WHERE phone=?', [email, phone]);
    }
    if (clientId && !existing.client_id) {
      await run('UPDATE contacts SET client_id=? WHERE phone=?', [clientId, phone]);
    }
  }
}

async function getOrCreateSession(phone, waId, agentId, flow, preview) {
  const active = await get("SELECT * FROM sessions WHERE phone=? AND wa_account_id=? AND status='active' ORDER BY id DESC LIMIT 1", [phone, waId]);
  if (active) {
    await run("UPDATE sessions SET preview=?,unread=1,last_message_at=datetime('now') WHERE id=?", [preview, active.id]);
    return await get('SELECT * FROM sessions WHERE id=?', [active.id]);
  }
  const r = await run('INSERT INTO sessions (phone,wa_account_id,agent_id,flow,preview) VALUES (?,?,?,?,?)', [phone, waId, agentId, flow||'cliente', preview]);
  return await get('SELECT * FROM sessions WHERE id=?', [r.lastID]);
}

async function buildEnrichedSession(sessionId) {
  const s = await get(`
    SELECT s.*,c.name,c.avatar,c.tags,c.contact_note,a.name agent_name,a.color agent_color,w.display_name wa_name
    FROM sessions s JOIN contacts c ON c.phone=s.phone JOIN agents a ON a.id=s.agent_id JOIN wa_accounts w ON w.id=s.wa_account_id
    WHERE s.id=?`, [sessionId]);
  return s ? enrichSession(s) : null;
}

// ─── Sesiones ─────────────────────────────────────────────
app.get('/api/sessions', auth, async (req, res) => {
  try {
    const dateRe = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?$/;
    const rawFrom   = req.query.from   || null;
    const rawTo     = req.query.to     || null;
    const rawPeriod = req.query.period || null;
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
  try { await run('UPDATE sessions SET unread=0 WHERE id=?', [+req.params.id]); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sessions/:id/review', auth, async (req, res) => {
  try {
    const { quality, note='' } = req.body;
    if (!['alta','media','baja'].includes(quality)) return res.status(400).json({ error: 'quality: alta|media|baja' });
    const id = +req.params.id;
    await run('INSERT INTO reviews (session_id,agent_id,quality,note) VALUES (?,?,?,?)', [id, req.user.id, quality, note]);
    await run('INSERT INTO messages (session_id,phone,direction,body,time_label) SELECT id,phone,?,?,? FROM sessions WHERE id=?',
      ['system', `Revisión · ${quality.toUpperCase()} · ${req.user.name}${note?' · '+note:''}`, nowTime(), id]);
    const s = await get('SELECT * FROM sessions WHERE id=?', [id]);
    const enriched = await buildEnrichedSession(id);
    broadcastTo(s.agent_id, 'review', { sessionId:id, conv:enriched });
    res.json(enriched);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sessions/:id/close', auth, async (req, res) => {
  try {
    const id = +req.params.id;
    await run("UPDATE sessions SET status='closed' WHERE id=?", [id]);
    await run('INSERT INTO messages (session_id,phone,direction,body,time_label) SELECT id,phone,?,?,? FROM sessions WHERE id=?',
      ['system','Sesión cerrada', nowTime(), id]);
    const s = await get('SELECT * FROM sessions WHERE id=?', [id]);
    const enriched = await buildEnrichedSession(id);
    broadcastTo(s.agent_id, 'sessionClosed', { sessionId:id, conv:enriched });
    res.json(enriched);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Contactos ────────────────────────────────────────────
app.patch('/api/contacts/:phone', auth, async (req, res) => {
  try {
    const { note='', tags=[] } = req.body;
    await run('UPDATE contacts SET contact_note=?,tags=? WHERE phone=?', [note, JSON.stringify(tags), req.params.phone]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Enviar mensaje ───────────────────────────────────────
app.post('/api/send', auth, async (req, res) => {
  const { phone, text, sessionId } = req.body;
  if (!phone||!text) return res.status(400).json({ error: 'Faltan phone y text' });
  const clean = phone.replace(/[\s+]/g,'');

  try {
    // Si hay sistema externo configurado, enviar por ahí
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
      // Envío directo por Meta API
      const wa = await get('SELECT * FROM wa_accounts WHERE agent_id=?', [req.user.id]);
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

    // Guardar en DB
    const sid = sessionId || (await get("SELECT id FROM sessions WHERE phone=? AND status='active' ORDER BY id DESC LIMIT 1", [clean]))?.id;
    if (sid) {
      await run('INSERT INTO messages (session_id,phone,direction,body,time_label) VALUES (?,?,?,?,?)', [sid, clean, 'out', text, nowTime()]);
      await run("UPDATE sessions SET preview=?,last_message_at=datetime('now') WHERE id=?", [text, sid]);
      const enriched = await buildEnrichedSession(sid);
      const s = await get('SELECT agent_id FROM sessions WHERE id=?', [sid]);
      broadcastTo(s.agent_id, 'message', { sessionId:sid, phone:clean, conv:enriched });
    }
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── Helper para parsear timestamps en varios formatos ────
function parseTimestamp(ts) {
  if (!ts) return null;
  // Formato DD/MM/YYYY HH:MM:SS o DD/MM/YYYY HH:MM o DD/MM/YYYY
  const ddmmyyyy = ts.match(/^(\d{2})\/(\d{2})\/(\d{4})(?:[T\s](\d{2}):(\d{2})(?::(\d{2}))?)?/);
  if (ddmmyyyy) {
    const [, dd, mm, yyyy, hh='00', min='00', ss='00'] = ddmmyyyy;
    return new Date(`${yyyy}-${mm}-${dd}T${hh}:${min}:${ss}+01:00`);
  }
  // Formato ISO u otros — dejar que Date lo parsee
  const d = new Date(ts);
  return isNaN(d.getTime()) ? null : d;
}

// ─── Integración sistema externo (AWS) ───────────────────
function externalAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== EXT_API_KEY) return res.status(401).json({ error: 'API Key inválida' });
  next();
}

// POST /messages/incoming — el sistema AWS nos envía mensajes
app.post('/messages/incoming', externalAuth, async (req, res) => {
  try {
    const { client_id, name, phone, email, message, timestamp, conversation_id, direction='incoming', flow='cliente', agent: agentHint } = req.body;
    if (!phone||!message) return res.status(400).json({ error: 'Faltan: phone, message' });

    const clean = phone.replace(/[\s+]/g,'');
    const text  = String(message).trim();
    const parsedTs = parseTimestamp(timestamp);
    const time  = parsedTs ? madridTime(parsedTs).toISOString().slice(11,16) : nowTime();
    const dir   = direction==='incoming' ? 'in' : 'bot';

    await upsertContact(clean, name, email, client_id);

    // Determinar agente y cuenta WA
    let wa = null, agentId = null;
    if (agentHint) {
      const ag = await get('SELECT id FROM agents WHERE username=?', [agentHint.toLowerCase()]);
      if (ag) { wa = await get('SELECT * FROM wa_accounts WHERE agent_id=?', [ag.id]); agentId = ag.id; }
    }
    if (!wa) {
      // Buscar sesión activa existente del contacto
      const existSess = await get("SELECT s.*,s.wa_account_id wa_id FROM sessions s WHERE s.phone=? AND s.status='active' ORDER BY s.id DESC LIMIT 1", [clean]);
      if (existSess) { wa = await get('SELECT * FROM wa_accounts WHERE id=?', [existSess.wa_id]); agentId = existSess.agent_id; }
    }
    if (!wa) {
      // Usar la primera cuenta WA disponible
      wa = await get('SELECT * FROM wa_accounts LIMIT 1');
      if (wa) agentId = wa.agent_id;
    }
    if (!wa||!agentId) return res.status(500).json({ error: 'No hay cuentas WA configuradas' });

    const session = await getOrCreateSession(clean, wa.id, agentId, flow, text);
    await run('INSERT INTO messages (session_id,phone,direction,body,meta_id,time_label) VALUES (?,?,?,?,?,?)',
      [session.id, clean, dir, text, conversation_id||null, time]);

    const enriched = await buildEnrichedSession(session.id);
    broadcastTo(agentId, 'message', { sessionId:session.id, phone:clean, conv:enriched });
    console.log(`📥 [AWS/${direction}] ${name||clean}: ${text.slice(0,60)}`);
    res.json({ ok:true, session_id:session.id });
  } catch(e) { console.error('/messages/incoming:', e.message); res.status(500).json({ error: e.message }); }
});

// POST /messages/outgoing — el sistema AWS confirma un mensaje saliente
app.post('/messages/outgoing', externalAuth, async (req, res) => {
  try {
    const { phone, message, timestamp, conversation_id } = req.body;
    if (!message) return res.status(400).json({ error: 'Falta message' });
    const clean = phone ? phone.replace(/[\s+]/g,'') : null;
    const text  = String(message).trim();
    const parsedTs = parseTimestamp(timestamp);
    const time  = parsedTs ? madridTime(parsedTs).toISOString().slice(11,16) : nowTime();

    if (clean) {
      const session = await get("SELECT * FROM sessions WHERE phone=? AND status='active' ORDER BY id DESC LIMIT 1", [clean]);
      if (session) {
        await run('INSERT INTO messages (session_id,phone,direction,body,meta_id,time_label) VALUES (?,?,?,?,?,?)',
          [session.id, clean, 'out', text, conversation_id||null, time]);
        await run("UPDATE sessions SET preview=?,last_message_at=datetime('now') WHERE id=?", [text, session.id]);
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

    // Sanitizar fechas — solo formato YYYY-MM-DD permitido
    const dateRe = /^\d{4}-\d{2}-\d{2}$/;
    const rawFrom   = req.query.from   || null;
    const rawTo     = req.query.to     || null;
    const rawPeriod = req.query.period || null;
    const validPeriods = ['today','week','month','quarter'];

    let dates = {
      from: rawFrom   && dateRe.test(rawFrom)   ? rawFrom   : null,
      to:   rawTo     && dateRe.test(rawTo)      ? rawTo     : null,
    };
    if (rawPeriod && validPeriods.includes(rawPeriod)) {
      const pd = periodDates(rawPeriod); if (pd) dates = pd;
    }
    const ac = aid ? `AND s.agent_id=${aid}` : '';
    const fc = dates.from ? `AND date(s.started_at)>='${dates.from}'` : '';
    const tc = dates.to   ? `AND date(s.started_at)<='${dates.to}'`   : '';
    const rc = dates.from ? `AND date(r.created_at)>='${dates.from}'` : '';
    const rt = dates.to   ? `AND date(r.created_at)<='${dates.to}'`   : '';

    const [summary, byQrows, agentRows, sessDay, revDay, topC, noReply] = await Promise.all([
      get(`SELECT COUNT(DISTINCT s.id) total_sessions, COUNT(DISTINCT CASE WHEN s.status='active' THEN s.id END) active_sessions, COUNT(DISTINCT CASE WHEN s.unread=1 AND s.status='active' THEN s.id END) unread, COUNT(DISTINCT c.phone) total_contacts, COUNT(r.id) total_reviews FROM sessions s JOIN contacts c ON c.phone=s.phone LEFT JOIN reviews r ON r.session_id=s.id WHERE 1=1 ${ac} ${fc} ${tc}`),
      all(`SELECT r.quality, COUNT(*) n FROM reviews r JOIN sessions s ON s.id=r.session_id WHERE 1=1 ${ac} ${rc} ${rt} GROUP BY r.quality`),
      all(`SELECT a.name, a.color, r.quality, COUNT(*) n FROM reviews r JOIN agents a ON a.id=r.agent_id JOIN sessions s ON s.id=r.session_id WHERE a.role='agent' ${rc} ${rt} GROUP BY a.name,r.quality`),
      all(`SELECT date(started_at) day, COUNT(*) n FROM sessions WHERE 1=1 ${ac} ${fc} ${tc} GROUP BY day ORDER BY day`),
      all(`SELECT date(r.created_at) day, r.quality, COUNT(*) n FROM reviews r JOIN sessions s ON s.id=r.session_id WHERE 1=1 ${ac} ${rc} ${rt} GROUP BY day,r.quality ORDER BY day`),
      all(`SELECT c.phone,c.name,COUNT(DISTINCT s.id) sessions,COUNT(CASE WHEN r.quality='alta' THEN 1 END) altas,COUNT(CASE WHEN r.quality='media' THEN 1 END) medias,COUNT(CASE WHEN r.quality='baja' THEN 1 END) bajas FROM contacts c JOIN sessions s ON s.phone=c.phone LEFT JOIN reviews r ON r.session_id=s.id WHERE 1=1 ${ac} ${fc} ${tc} GROUP BY c.phone ORDER BY sessions DESC LIMIT 10`),
      all(`SELECT s.id session_id,s.phone,c.name,c.avatar,a.name agent_name,a.color agent_color,w.display_name wa_name,lm.body last_body,lm.created_at last_msg_at,CAST(julianday('now')-julianday(lm.created_at) AS INTEGER) days_waiting FROM sessions s JOIN contacts c ON c.phone=s.phone JOIN agents a ON a.id=s.agent_id JOIN wa_accounts w ON w.id=s.wa_account_id JOIN messages lm ON lm.id=(SELECT id FROM messages WHERE session_id=s.id AND direction IN ('out','bot') ORDER BY id DESC LIMIT 1) WHERE s.status='active' ${ac} AND NOT EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction='in' AND created_at>lm.created_at) AND julianday('now')-julianday(lm.created_at)>3 ORDER BY days_waiting DESC`),
    ]);

    const wDates = periodDates('week');
    const mDates = periodDates('month');
    const [repliedW, notRepliedW, repliedM, notRepliedM] = await Promise.all([
      get(`SELECT COUNT(DISTINCT s.id) n FROM sessions s WHERE ${ac?ac.replace('AND ',''):'1=1'} AND date(s.started_at)>='${wDates.from}' AND date(s.started_at)<='${wDates.to}' AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) AND EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot')))`),
      get(`SELECT COUNT(DISTINCT s.id) n FROM sessions s WHERE ${ac?ac.replace('AND ',''):'1=1'} AND date(s.started_at)>='${wDates.from}' AND date(s.started_at)<='${wDates.to}' AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) AND NOT EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot'))) AND julianday('now')-julianday(s.last_message_at)>3`),
      get(`SELECT COUNT(DISTINCT s.id) n FROM sessions s WHERE ${ac?ac.replace('AND ',''):'1=1'} AND date(s.started_at)>='${mDates.from}' AND date(s.started_at)<='${mDates.to}' AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) AND EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot')))`),
      get(`SELECT COUNT(DISTINCT s.id) n FROM sessions s WHERE ${ac?ac.replace('AND ',''):'1=1'} AND date(s.started_at)>='${mDates.from}' AND date(s.started_at)<='${mDates.to}' AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) AND NOT EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot'))) AND julianday('now')-julianday(s.last_message_at)>3`),
    ]);

    const [weeklyRate, monthlyRate] = await Promise.all([
      all(`SELECT strftime('%Y-W%W',s.started_at) week,COUNT(DISTINCT s.id) total,COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot'))) THEN s.id END) replied FROM sessions s WHERE s.started_at>=date('now','-90 days') ${ac} AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) GROUP BY week ORDER BY week ASC`),
      all(`SELECT strftime('%Y-%m',s.started_at) month,COUNT(DISTINCT s.id) total,COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM messages mi WHERE mi.session_id=s.id AND mi.direction='in' AND mi.created_at>(SELECT MAX(created_at) FROM messages WHERE session_id=s.id AND direction IN ('out','bot'))) THEN s.id END) replied FROM sessions s WHERE s.started_at>=date('now','-365 days') ${ac} AND EXISTS(SELECT 1 FROM messages WHERE session_id=s.id AND direction IN ('out','bot')) GROUP BY month ORDER BY month ASC`),
    ]);

    const dayMap = {};
    revDay.forEach(r => { if(!dayMap[r.day]) dayMap[r.day]={alta:0,media:0,baja:0}; dayMap[r.day][r.quality]=r.n; });
    sessDay.forEach(r=> { if(!dayMap[r.day]) dayMap[r.day]={alta:0,media:0,baja:0}; dayMap[r.day].total=r.n; });
    const byAgent = {};
    agentRows.forEach(r => { if(!byAgent[r.name]) byAgent[r.name]={color:r.color,alta:0,media:0,baja:0}; byAgent[r.name][r.quality]=r.n; });

    res.json({
      period: dates,
      summary: { ...summary, thisMonth: (await get(`SELECT COUNT(*) n FROM sessions WHERE strftime('%Y-%m',started_at)=strftime('%Y-%m','now') ${ac}`)).n },
      byQuality: Object.fromEntries(byQrows.map(r=>[r.quality,r.n])),
      byAgent,
      qualityPerDay: Object.entries(dayMap).sort(([a],[b])=>a.localeCompare(b)).map(([day,v])=>({day,...v})),
      topContacts: topC,
      agents: req.user.role==='admin' ? await all('SELECT id,username,name,role,color FROM agents') : [],
      noReply: noReply.map(r=>({ sessionId:r.session_id, phone:r.phone, name:r.name, avatar:r.avatar, agentName:r.agent_name, agentColor:r.agent_color, waName:r.wa_name, lastBody:r.last_body, lastMsgAt:r.last_msg_at, daysWaiting:r.days_waiting })),
      responseRate: {
        week:  { label:'Últimos 7 días (+3 espera)', from:wDates.from, to:wDates.to, replied:repliedW.n,  notReplied:notRepliedW.n,  total:repliedW.n+notRepliedW.n   },
        month: { label:'Último mes (+3 espera)',     from:mDates.from, to:mDates.to, replied:repliedM.n,  notReplied:notRepliedM.n,  total:repliedM.n+notRepliedM.n   },
      },
      weeklyRate:  weeklyRate.map(r=>({ period:r.week,  total:r.total, replied:r.replied, notReplied:r.total-r.replied })),
      monthlyRate: monthlyRate.map(r=>({ period:r.month, total:r.total, replied:r.replied, notReplied:r.total-r.replied })),
    });
  } catch(e) { console.error('/api/analytics:', e.message); res.status(500).json({ error: e.message }); }
});

// ─── Admin ────────────────────────────────────────────────
app.get('/api/admin/agents',      auth, adminOnly, async (req,res) => res.json(await all('SELECT id,username,name,role,color FROM agents')));
app.get('/api/admin/wa-accounts', auth, adminOnly, async (req,res) => res.json(await all('SELECT w.*,a.name agent_name,a.color agent_color FROM wa_accounts w JOIN agents a ON a.id=w.agent_id')));

app.patch('/api/admin/wa-accounts/:id', auth, adminOnly, async (req, res) => {
  try {
    const { phone_number_id, wa_token, verify_token, display_name } = req.body;
    await run('UPDATE wa_accounts SET phone_number_id=COALESCE(?,phone_number_id),wa_token=COALESCE(?,wa_token),verify_token=COALESCE(?,verify_token),display_name=COALESCE(?,display_name) WHERE id=?',
      [phone_number_id||null, wa_token||null, verify_token||null, display_name||null, +req.params.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.patch('/api/admin/agents/:id/password', auth, adminOnly, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password||password.length<6) return res.status(400).json({ error:'Mínimo 6 caracteres' });
    await run('UPDATE agents SET password=? WHERE id=?', [bcrypt.hashSync(password,10), +req.params.id]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ─── Reset BD — borra todas las conversaciones, mensajes y contactos ──
app.post('/api/admin/reset', auth, adminOnly, async (req, res) => {
  try {
    await run('DELETE FROM messages');
    await run('DELETE FROM reviews');
    await run('DELETE FROM sessions');
    await run('DELETE FROM contacts');
    await run('DELETE FROM login_attempts');
    console.log(`🗑️  BD reseteada por ${req.user.username}`);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ─── Seed demo — solo disponible en entorno TEST ──────────
app.post('/api/demo/seed', async (req, res) => {
  if (!IS_TEST) return res.status(403).json({ error: 'No disponible en producción' });
  try {
    const angel = await get('SELECT id FROM agents WHERE username=?',['angel']);
    const clara = await get('SELECT id FROM agents WHERE username=?',['clara']);
    const waA   = await get('SELECT * FROM wa_accounts WHERE agent_id=?',[angel.id]);
    const waC   = await get('SELECT * FROM wa_accounts WHERE agent_id=?',[clara.id]);

    const contacts = [['34612345678','María García','MG'],['34634567890','Carlos López','CL'],['34698123456','Ana Martínez','AM'],['34677890234','Pedro Sánchez','PS'],['34655432109','Laura Fernández','LF'],['34698765432','Javier Moreno','JM']];
    for (const [p,n,av] of contacts) {
      const ex = await get('SELECT phone FROM contacts WHERE phone=?',[p]);
      if (!ex) await run('INSERT INTO contacts (phone,name,avatar) VALUES (?,?,?)',[p,n,av]);
    }

    const hist = [
      {phone:'34612345678',wa:waA,ag:angel,flow:'cliente',days:14,msgs:[['in','Quiero el X300'],['out','Claro'],['in','Lo compro']],revs:[{q:'alta',note:'Compra cerrada'}]},
      {phone:'34612345678',wa:waA,ag:angel,flow:'cliente',days:7, msgs:[['in','Duda envío'],['out','Te explico'],['in','Gracias']],revs:[{q:'media',note:''},{q:'alta',note:'Resuelta'}]},
      {phone:'34634567890',wa:waA,ag:angel,flow:'crm',    days:20,msgs:[['bot','[CRM] #3210'],['in','Gracias']],revs:[{q:'alta',note:'VIP'}]},
      {phone:'34698123456',wa:waC,ag:clara,flow:'mkt',    days:12,msgs:[['bot','[Mkt] Oferta'],['in','k']],revs:[{q:'baja',note:'Sin interés'}]},
      {phone:'34698123456',wa:waC,ag:clara,flow:'mkt',    days:3, msgs:[['bot','[Mkt] Nueva'],['in','¿Cuánto?'],['out','Te mando']],revs:[{q:'media',note:''},{q:'media',note:'2ª rev'}]},
      {phone:'34677890234',wa:waC,ag:clara,flow:'cliente',days:10,msgs:[['in','hola'],['bot','¡Hola!'],['in','no']],revs:[{q:'baja',note:'No interesado'}]},
      {phone:'34655432109',wa:waA,ag:angel,flow:'crm',    days:18,msgs:[['bot','[CRM] Prop'],['in','Revisamos'],['out','Ok']],revs:[{q:'alta',note:'Distribuidor'}]},
      {phone:'34698765432',wa:waA,ag:angel,flow:'cliente',days:9, msgs:[['in','500 uds/mes'],['out','Preparamos'],['in','Ok']],revs:[{q:'alta',note:'Oportunidad'}]},
      {phone:'34698765432',wa:waA,ag:angel,flow:'cliente',days:5, msgs:[['out','¿Seguís interesados?']],revs:[]},
    ];

    for (const s of hist) {
      const d = new Date(); d.setDate(d.getDate()-s.days);
      const start = new Date(d); start.setHours(9,0,0,0);
      const end   = new Date(start); end.setHours(10,30,0,0);
      const r = await run('INSERT OR IGNORE INTO sessions (phone,wa_account_id,agent_id,flow,status,preview,started_at,last_message_at,unread) VALUES (?,?,?,?,?,?,?,?,0)',
        [s.phone,s.wa.id,s.ag.id,s.flow,'closed',s.msgs[s.msgs.length-1][1],start.toISOString(),end.toISOString()]);
      if (!r.lastID) continue;
      for (let i=0;i<s.msgs.length;i++) {
        const t=new Date(start);t.setMinutes(t.getMinutes()+i*5);
        await run('INSERT INTO messages (session_id,phone,direction,body,time_label) VALUES (?,?,?,?,?)',[r.lastID,s.phone,s.msgs[i][0],s.msgs[i][1],madridTime(t).toISOString().slice(11,16)]);
      }
      for (let i=0;i<s.revs.length;i++) {
        const t=new Date(end);t.setMinutes(t.getMinutes()+i*10);
        await run('INSERT INTO reviews (session_id,agent_id,quality,note,created_at) VALUES (?,?,?,?,?)',[r.lastID,s.ag.id,s.revs[i].q,s.revs[i].note,t.toISOString()]);
        await run('INSERT INTO messages (session_id,phone,direction,body,time_label) VALUES (?,?,?,?,?)',[r.lastID,s.phone,'system',`Revisión · ${s.revs[i].q.toUpperCase()}${s.revs[i].note?' · '+s.revs[i].note:''}`,madridTime(t).toISOString().slice(11,16)]);
      }
    }

    const active = [
      {phone:'34612345678',wa:waA,ag:angel,flow:'cliente',msgs:[['in','¿Stock del X300?']]},
      {phone:'34634567890',wa:waA,ag:angel,flow:'crm',    msgs:[['bot','[CRM] #4521'],['out','Confirmado'],['in','¿Express?']]},
      {phone:'34698765432',wa:waA,ag:angel,flow:'cliente',msgs:[['in','¿La propuesta?'],['in','Urgente']]},
      {phone:'34698123456',wa:waC,ag:clara,flow:'mkt',    msgs:[['bot','[Mkt] Primavera'],['in','¿Cuánto?']]},
      {phone:'34655432109',wa:waC,ag:clara,flow:'crm',    msgs:[['in','Ampliar pedido']]},
    ];

    for (const s of active) {
      const ex = await get("SELECT id FROM sessions WHERE phone=? AND wa_account_id=? AND status='active'",[s.phone,s.wa.id]);
      if (ex) continue;
      const r = await run('INSERT INTO sessions (phone,wa_account_id,agent_id,flow,preview) VALUES (?,?,?,?,?)',[s.phone,s.wa.id,s.ag.id,s.flow,s.msgs[s.msgs.length-1][1]]);
      for (let i=0;i<s.msgs.length;i++) await run('INSERT INTO messages (session_id,phone,direction,body,time_label) VALUES (?,?,?,?,?)',[r.lastID,s.phone,s.msgs[i][0],s.msgs[i][1],`${9+i}:0${i}`]);
    }

    res.json({ ok:true, logins:{ admin:'admin123', angel:'angel123', clara:'clara123' } });
  } catch(e) { console.error('Seed error:',e); res.status(500).json({ error:e.message }); }
});

// ─── Manejador global de errores ─────────────────────────
app.use((err, req, res, next) => {
  console.error('Error no controlado:', err.message);
  res.status(500).json({
    error: IS_TEST ? err.message : 'Error interno del servidor'
  });
});

// ─── Arrancar ─────────────────────────────────────────────
initDB().then(async () => {
  app.listen(PORT, async () => {
    console.log(`
╔══════════════════════════════════════════════════════╗
║  ${IS_TEST ? '🟡  WA Manager Pro  [ENTORNO TEST]' : '🟢  WA Manager Pro  →  PRODUCCIÓN    '}  :${PORT}  ║
╠══════════════════════════════════════════════════════╣
║  DB: ${dbFile.padEnd(47)}║
║  Sistema externo (AWS):                              ║
║    POST /messages/incoming  (header X-Api-Key)       ║
║    POST /messages/outgoing  (header X-Api-Key)       ║
║  Webhooks Meta:                                      ║
║    GET|POST /webhook/verify_angel                    ║
║    GET|POST /webhook/verify_clara                    ║${IS_TEST ? `
║  ⚠️  TEST: seed demo auto, contraseñas por defecto   ║` : ''}
║  Demo: POST /api/demo/seed                           ║
╚══════════════════════════════════════════════════════╝`);

    // Auto-seed solo en TEST y solo si la BD está vacía
    if (IS_TEST) {
      const count = await get('SELECT COUNT(*) n FROM sessions').catch(() => ({ n: 0 }));
      if (count.n === 0) {
        console.log('🌱 TEST: ejecutando seed de demo automático...');
        await fetch(`http://localhost:${PORT}/api/demo/seed`, { method: 'POST' })
          .then(() => console.log('✅ Seed demo completado'))
          .catch(e => console.warn('⚠️  Seed demo falló:', e.message));
      }
    }
  });
}).catch(e => { console.error('Error iniciando DB:', e); process.exit(1); });
