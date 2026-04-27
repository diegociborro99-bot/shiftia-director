const express = require('express');
const path = require('path');
const http = require('http');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const PKG_VERSION = (() => { try { return require('./package.json').version; } catch (e) { return '0.0.0'; } })();

// ====== STARTUP BANNER ======
console.log('========================================');
console.log(`  Shiftia Director v${PKG_VERSION} starting`);
console.log(`  NODE_ENV=${process.env.NODE_ENV || 'development'}`);
console.log(`  PORT=${PORT}`);
console.log('========================================');

// ====== JWT SECRET — obligatorio en producción ======
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (IS_PRODUCTION) {
    console.error('[FATAL] JWT_SECRET env var REQUIRED in production. Refusing to start.');
    process.exit(1);
  }
  const crypto = require('crypto');
  JWT_SECRET = 'dev-only-' + crypto.randomBytes(16).toString('hex');
  console.warn('[SECURITY] JWT_SECRET not set — using ephemeral DEV secret. Sessions will reset on restart.');
}

// ====== TRUST PROXY ======
// Detrás de Railway/Heroku necesario para req.ip real, rate limiting, secure cookies
app.set('trust proxy', 1);

// ====== WEBSOCKET SERVER (real-time sync) ======
const wss = new WebSocket.Server({ server, path: '/ws' });
const wsClients = new Map(); // userId → Set<ws>

wss.on('connection', (ws, req) => {
  // Authentication via message (more secure than URL query params)
  ws.isAuthenticated = false;

  // Auto-close if not authenticated within 10 seconds
  const authTimeout = setTimeout(() => {
    if (!ws.isAuthenticated) {
      ws.close(4001, 'Auth timeout');
    }
  }, 10000);

  // Authentication only via message (query param auth removed for security)
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);

      // Handle auth message
      if (data.type === 'auth' && !ws.isAuthenticated) {
        try {
          const decoded = jwt.verify(data.token, JWT_SECRET);
          ws.userId = decoded.id;
          ws.userEmail = decoded.email;
          ws.isAuthenticated = true;
          clearTimeout(authTimeout);
          if (!wsClients.has(decoded.id)) wsClients.set(decoded.id, new Set());
          wsClients.get(decoded.id).add(ws);
          console.log(`[WS] ${decoded.email} connected via message (${wsClients.get(decoded.id).size} sessions)`);
          broadcastToUser(decoded.id, { type: 'sessions', count: wsClients.get(decoded.id).size });
        } catch (authErr) {
          ws.close(4001, 'Invalid token');
        }
        return;
      }

      // All other messages require authentication
      if (!ws.isAuthenticated) return;

      if (data.type === 'shift_change') {
        broadcastToUser(ws.userId, { type: 'shift_change', payload: data.payload, from: ws.userEmail }, ws);
      }
    } catch (e) { /* ignore bad messages */ }
  });

  ws.on('close', () => {
    clearTimeout(authTimeout);
    if (ws.userId) {
      const set = wsClients.get(ws.userId);
      if (set) {
        set.delete(ws);
        if (set.size === 0) wsClients.delete(ws.userId);
        else broadcastToUser(ws.userId, { type: 'sessions', count: set.size });
      }
    }
  });
});

function broadcastToUser(userId, data, excludeWs) {
  const set = wsClients.get(userId);
  if (!set) return;
  const msg = JSON.stringify(data);
  set.forEach(client => {
    if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
      client.send(msg, (err) => {
        if (err) {
          console.warn('[WS] Send failed, removing client:', err.message);
          set.delete(client);
          if (set.size === 0) wsClients.delete(userId);
        }
      });
    }
  });
}

// Periodic cleanup of stale WebSocket connections + heartbeat
// Heartbeat: marca isAlive=false; en pong → true. Si en el siguiente tick
// sigue false → la conexión está muerta, la cerramos.
wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
});

setInterval(() => {
  wsClients.forEach((set, userId) => {
    set.forEach(ws => {
      if (ws.readyState !== WebSocket.OPEN) {
        set.delete(ws);
        return;
      }
      if (ws.isAlive === false) {
        try { ws.terminate(); } catch (e) {}
        set.delete(ws);
        return;
      }
      ws.isAlive = false;
      try { ws.ping(); } catch (e) {}
    });
    if (set.size === 0) wsClients.delete(userId);
  });
}, 30000);

// ====== SECURITY HEADERS (helmet ligero, sin dependencia extra) ======
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (IS_PRODUCTION) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  // Eliminamos el header X-Powered-By: Express (info leak)
  res.removeHeader('X-Powered-By');
  next();
});

// ====== CORS — explícito, no abierto ======
app.use((req, res, next) => {
  const allowed = (process.env.CORS_ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const origin = req.headers.origin;
  // Si no hay configuración explícita: same-origin only (no CORS)
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS' && origin && allowed.includes(origin)) return res.status(204).end();
  next();
});

// ====== BODY LIMITS — DoS protection ======
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ====== RATE LIMITING in-memory (sin dependencia extra) ======
// Buckets por IP+ruta. Si la ruta es de auth, límite más estricto.
const rateBuckets = new Map();
function rateLimit(opts) {
  const max = opts.max || 60;
  const windowMs = opts.windowMs || 60000;
  return function (req, res, next) {
    const key = (req.ip || req.connection.remoteAddress || 'unknown') + '::' + (opts.scope || req.path);
    const now = Date.now();
    let bucket = rateBuckets.get(key);
    if (!bucket || now - bucket.start > windowMs) {
      bucket = { count: 0, start: now };
      rateBuckets.set(key, bucket);
    }
    bucket.count++;
    if (bucket.count > max) {
      const retryAfter = Math.ceil((bucket.start + windowMs - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({ error: 'Demasiadas peticiones. Espera ' + retryAfter + 's.' });
    }
    next();
  };
}
// Limpieza periódica
setInterval(() => {
  const now = Date.now();
  rateBuckets.forEach((b, k) => { if (now - b.start > 5 * 60000) rateBuckets.delete(k); });
}, 60000);

// Rate limits específicos para auth (montados sobre las rutas más abajo)
const authLimiter = rateLimit({ max: 10, windowMs: 60000, scope: 'auth' });        // 10/min por IP
const writeLimiter = rateLimit({ max: 60, windowMs: 60000, scope: 'write' });      // 60/min por IP en saves

// ====== DATABASE CONFIG ======
// Filter out undefined values to avoid overriding connectionString
const poolConfig = process.env.DATABASE_URL
  ? { connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }
  : {
      host: process.env.PGHOST,
      port: process.env.PGPORT || 5432,
      database: process.env.PGDATABASE,
      user: process.env.PGUSER,
      password: process.env.PGPASSWORD,
    };

const pool = new Pool(poolConfig);
let dbAvailable = false;

// Test database connection
pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  dbAvailable = false;
});

// ====== DATABASE INITIALIZATION ======
async function initializeDatabase() {
  let client;
  try {
    client = await pool.connect();

    // Create users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        company VARCHAR(255),
        plan VARCHAR(50) DEFAULT 'trial',
        plan_status VARCHAR(50) DEFAULT 'active',
        workers_limit INTEGER DEFAULT 25,
        next_billing_date DATE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create support tickets table
    await client.query(`
      CREATE TABLE IF NOT EXISTS support_tickets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        category VARCHAR(50) DEFAULT 'general',
        subject VARCHAR(500) NOT NULL,
        message TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create bookings table
    await client.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(50) NOT NULL,
        company VARCHAR(255),
        workers VARCHAR(50),
        department VARCHAR(255),
        message TEXT,
        booking_date DATE NOT NULL,
        booking_time VARCHAR(10) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create contact leads table
    await client.query(`
      CREATE TABLE IF NOT EXISTS contact_leads (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        company VARCHAR(255),
        workers VARCHAR(50),
        department VARCHAR(255),
        message TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create schedule data table (stores entire SARA workspace per user)
    await client.query(`
      CREATE TABLE IF NOT EXISTS schedule_data (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        data JSONB NOT NULL DEFAULT '{}',
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id)
      );
    `);

    // Create audit logs table (server-side change history)
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        action VARCHAR(100) NOT NULL,
        details JSONB DEFAULT '{}',
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create schedule backups table (automatic daily snapshots)
    await client.query(`
      CREATE TABLE IF NOT EXISTS schedule_backups (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        data JSONB NOT NULL DEFAULT '{}',
        backup_type VARCHAR(20) DEFAULT 'auto',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log('Database initialized: all tables created');

    // Seed Sara admin user (SAV)
    const saraEmail = 'director@shiftia.es';
    const existingSara = await client.query('SELECT id FROM users WHERE email = $1', [saraEmail]);

    if (existingSara.rows.length === 0) {
      const adminPass = process.env.ADMIN_PASSWORD;
      if (!adminPass) {
        if (IS_PRODUCTION) {
          console.error('[FATAL] No admin user exists and ADMIN_PASSWORD env var is not set in production. Refusing to create with default password.');
          // No hacemos exit para no tirar el servicio: simplemente no creamos admin.
          // El operador debe definir ADMIN_PASSWORD y reiniciar.
        } else {
          console.warn('[SECURITY] ADMIN_PASSWORD env var not set — skipping admin seed. Define it for first admin.');
        }
      } else {
        if (adminPass.length < 12) {
          console.warn('[SECURITY] ADMIN_PASSWORD is shorter than 12 chars. Use a stronger password.');
        }
        const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
        const hashedPassword = await bcrypt.hash(adminPass, BCRYPT_ROUNDS);
        await client.query(`
          INSERT INTO users (email, password_hash, name, company, plan, plan_status, workers_limit)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [saraEmail, hashedPassword, 'Director', 'Hospital', 'enterprise', 'active', 1000]);
        console.log('[INIT] Admin user created successfully.');
      }
    }

    client.release();
    dbAvailable = true;
    console.log('[DB] PostgreSQL connected successfully');
  } catch (err) {
    console.error('Database initialization error:', err.message);
    console.warn('[DB] Running in localStorage-only mode (no PostgreSQL). Data will persist client-side only.');
    dbAvailable = false;
    if (client) try { client.release(); } catch(e) {}
    // Don't exit — run without DB, client uses localStorage fallback
  }
}

// ====== MIDDLEWARE ======
// JWT Authentication Middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification error:', err.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ====== HELPER FUNCTIONS ======
// Validate email format
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// ====== EMAIL CONFIG ======
// Pool de conexiones SMTP — reutilizable, max 5 simultáneas
let transporter = null;
function getTransporter() {
  if (transporter) return transporter;
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) {
    console.warn('[EMAIL] GMAIL_USER o GMAIL_APP_PASSWORD no configurados — los envíos fallarán silenciosamente.');
    return null;
  }
  transporter = nodemailer.createTransport({
    service: 'gmail',
    pool: true,
    maxConnections: 5,
    maxMessages: 100,
    auth: { user, pass }
  });
  return transporter;
}

// Safe wrapper: si no hay transporter configurado, no rompe — solo loguea
function safeSendMail(opts) {
  const t = getTransporter();
  if (!t) {
    return Promise.reject(new Error('SMTP no configurado'));
  }
  return t.sendMail(opts);
}

// ====== AUTHENTICATION ROUTES ======
// POST /api/auth/register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  if (!dbAvailable) return res.status(503).json({ error: 'Base de datos no disponible. Use login directo.' });
  try {
    const { email, password, name, company } = req.body;

    // Validate required fields
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    // Validate email format
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Validate password strength (at least 8 chars)
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Check if email already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    // Hash password (bcrypt rounds configurable, default 12)
    const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, company, plan, plan_status, workers_limit)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, email, name, company, plan, plan_status, workers_limit, created_at`,
      [email.toLowerCase(), passwordHash, name, company || null, 'trial', 'active', 25]
    );

    const user = result.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.status(201).json({ token, user });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Error creating account' });
  }
});

// Username → email mapping for single-user mode
const USERNAME_MAP = {
  'icueva': 'director@shiftia.es',
};

// POST /api/auth/login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body;

    // Resolve login identifier: username (SAV) or email
    let loginEmail = email;
    if (username && !email) {
      loginEmail = USERNAME_MAP[username.toLowerCase()] || username.toLowerCase();
    }

    // Validate required fields
    if (!loginEmail || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña son obligatorios' });
    }

    // No-DB mode: en producción rechazamos. En dev permitimos auth offline para testing local.
    if (!dbAvailable) {
      if (IS_PRODUCTION) {
        return res.status(503).json({ error: 'Servicio no disponible (BD desconectada). Inténtalo de nuevo en unos minutos.' });
      }
      // En dev: solo auth offline si la password coincide con DEV_OFFLINE_PASS env var
      const offlinePass = process.env.DEV_OFFLINE_PASS;
      if (!offlinePass || password !== offlinePass) {
        return res.status(503).json({ error: 'BD no disponible y DEV_OFFLINE_PASS no coincide.' });
      }
      const token = jwt.sign({ id: 1, email: loginEmail }, JWT_SECRET, { expiresIn: '30d' });
      return res.json({ token, user: { id: 1, email: loginEmail, name: 'Director', company: 'Hospital (offline)', plan: 'enterprise', plan_status: 'active', workers_limit: 1000 } });
    }

    // Find user by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [loginEmail.toLowerCase()]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Compare password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Return user without password_hash
    const { password_hash, ...userWithoutPassword } = user;

    // Audit log login
    logAudit(user.id, 'login', { email: user.email }, req.ip || req.connection.remoteAddress);

    res.json({ token, user: userWithoutPassword });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /api/auth/me (protected)
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  if (!dbAvailable) {
    return res.json({ user: { id: 1, email: req.user.email || 'director@shiftia.es', name: 'Director', company: 'Hospital', plan: 'enterprise', plan_status: 'active', workers_limit: 1000 } });
  }
  try {
    const result = await pool.query(
      'SELECT id, email, name, company, plan, plan_status, workers_limit, next_billing_date, created_at, updated_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Get user error:', err.message);
    res.status(500).json({ error: 'Error fetching user' });
  }
});

// PUT /api/auth/update (protected)
app.put('/api/auth/update', authMiddleware, async (req, res) => {
  try {
    const { name, email, company, password } = req.body;
    const userId = req.user.id;

    // Validate at least one field
    if (!name && !email && !company && !password) {
      return res.status(400).json({ error: 'At least one field is required' });
    }

    // Start building the update query
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (name) {
      updates.push(`name = $${paramCount}`);
      values.push(name);
      paramCount++;
    }

    if (email) {
      if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }
      // Check if email is already taken by another user
      const existingUser = await pool.query('SELECT id FROM users WHERE email = $1 AND id != $2', [email.toLowerCase(), userId]);
      if (existingUser.rows.length > 0) {
        return res.status(409).json({ error: 'Email already in use' });
      }
      updates.push(`email = $${paramCount}`);
      values.push(email.toLowerCase());
      paramCount++;
    }

    if (company) {
      updates.push(`company = $${paramCount}`);
      values.push(company);
      paramCount++;
    }

    if (password) {
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
      }
      const passwordHash = await bcrypt.hash(password, 10);
      updates.push(`password_hash = $${paramCount}`);
      values.push(passwordHash);
      paramCount++;
    }

    updates.push(`updated_at = NOW()`);

    values.push(userId);

    const query = `
      UPDATE users
      SET ${updates.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, email, name, company, plan, plan_status, workers_limit, next_billing_date, created_at, updated_at
    `;

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Update user error:', err.message);
    res.status(500).json({ error: 'Error updating user' });
  }
});

// ====== AUDIT LOG HELPER ======
async function logAudit(userId, action, details, ip) {
  try {
    await pool.query(
      'INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES ($1, $2, $3, $4)',
      [userId, action, JSON.stringify(details || {}), ip || null]
    );
  } catch (e) {
    console.warn('[Audit] Log failed:', e.message);
  }
}

// ====== AUTO-BACKUP LOGIC ======
async function createAutoBackup(userId) {
  try {
    // Check last backup time — only backup once per hour max
    const lastBackup = await pool.query(
      "SELECT created_at FROM schedule_backups WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
      [userId]
    );
    if (lastBackup.rows.length > 0) {
      const hourAgo = new Date(Date.now() - 60 * 60 * 1000);
      if (new Date(lastBackup.rows[0].created_at) > hourAgo) return; // Too recent
    }

    // Get current data and create snapshot
    const current = await pool.query('SELECT data FROM schedule_data WHERE user_id = $1', [userId]);
    if (current.rows.length === 0) return;

    await pool.query(
      'INSERT INTO schedule_backups (user_id, data, backup_type) VALUES ($1, $2, $3)',
      [userId, JSON.stringify(current.rows[0].data), 'auto']
    );

    // Keep only last 30 backups per user
    await pool.query(`
      DELETE FROM schedule_backups WHERE id IN (
        SELECT id FROM schedule_backups WHERE user_id = $1
        ORDER BY created_at DESC OFFSET 30
      )
    `, [userId]);

    console.log(`[Backup] Auto-backup created for user ${userId}`);
  } catch (e) {
    console.warn('[Backup] Auto-backup failed:', e.message);
  }
}

// ====== SCHEDULE DATA ROUTES ======
// GET /api/data (protected) — Load user's SARA workspace data
app.get('/api/data', authMiddleware, async (req, res) => {
  if (!dbAvailable) return res.json({}); // No DB — client uses localStorage
  try {
    const result = await pool.query(
      'SELECT data FROM schedule_data WHERE user_id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.json({}); // No data yet — fresh workspace
    }

    res.json(result.rows[0].data);
  } catch (err) {
    console.error('Load data error:', err.message);
    res.json({}); // Fallback to empty — client uses localStorage
  }
});

// POST /api/data (protected) — Save user's workspace data
app.post('/api/data', writeLimiter, authMiddleware, async (req, res) => {
  if (!dbAvailable) return res.json({ success: true }); // No DB — client uses localStorage
  try {
    const data = req.body;

    if (!data || typeof data !== 'object') {
      return res.status(400).json({ error: 'Invalid data format' });
    }

    // Upsert: insert or update
    await pool.query(`
      INSERT INTO schedule_data (user_id, data, updated_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (user_id) DO UPDATE
      SET data = $2, updated_at = NOW()
    `, [req.user.id, JSON.stringify(data)]);

    // Audit log
    const ip = req.ip || req.connection.remoteAddress;
    logAudit(req.user.id, 'data_save', { size: JSON.stringify(data).length }, ip).catch(() => {});

    // Auto-backup (max 1/hour)
    createAutoBackup(req.user.id).catch(e => console.warn('[Backup] Failed:', e.message));

    // Notify other sessions via WebSocket
    broadcastToUser(req.user.id, { type: 'data_saved', timestamp: Date.now() });

    res.json({ success: true });
  } catch (err) {
    console.error('Save data error:', err.message);
    res.json({ success: true }); // Don't crash — client uses localStorage
  }
});

// POST /api/support (protected)
app.post('/api/support', authMiddleware, async (req, res) => {
  try {
    const { category, subject, message } = req.body;

    // Validate required fields
    if (!subject || !message) {
      return res.status(400).json({ error: 'Subject and message are required' });
    }

    // Get user details
    const userResult = await pool.query(
      'SELECT email, name, company FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    const cat = category || 'general';
    const catLabels = { general: 'Consulta general', bug: 'Reporte de error', billing: 'Facturación', feature: 'Sugerencia de mejora' };

    // Save ticket to database (primary)
    try {
      await pool.query(
        'INSERT INTO support_tickets (user_id, category, subject, message) VALUES ($1, $2, $3, $4)',
        [req.user.id, cat, subject, message]
      );
    } catch (dbErr) {
      if (dbErr.message.includes('does not exist')) {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS support_tickets (
            id SERIAL PRIMARY KEY, user_id INTEGER, category VARCHAR(50) DEFAULT 'general',
            subject VARCHAR(500) NOT NULL, message TEXT NOT NULL,
            status VARCHAR(50) DEFAULT 'open', created_at TIMESTAMP DEFAULT NOW()
          );
        `);
        await pool.query(
          'INSERT INTO support_tickets (user_id, category, subject, message) VALUES ($1, $2, $3, $4)',
          [req.user.id, cat, subject, message]
        );
      } else {
        console.warn('DB insert ticket failed (continuing):', dbErr.message);
      }
    }

    console.log(`Support ticket from ${user.name} <${user.email}>: [${cat}] ${subject}`);
    res.json({ ok: true });

    // Fire-and-forget email (don't block response)
    try {
      if (process.env.GMAIL_APP_PASSWORD) {
        safeSendMail({
          from: `"Shiftia Support" <${process.env.GMAIL_USER || 'highkeycvsender@gmail.com'}>`,
          to: process.env.SUPPORT_EMAIL || 'highkeycvsender@gmail.com',
          subject: `[Soporte - ${catLabels[cat] || cat}] ${subject}`,
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 32px;">
              <div style="background: linear-gradient(135deg, #4ecdc4, #2980b9); padding: 24px 32px; border-radius: 12px 12px 0 0;">
                <h1 style="color: white; margin: 0; font-size: 1.4rem;">${catLabels[cat] || cat}: ${subject}</h1>
              </div>
              <div style="background: #f8fafc; padding: 32px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px;">
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 24px;">
                  <tr><td style="padding: 10px 0; color: #64748b; font-weight: 600; width: 110px;">Nombre</td><td style="padding: 10px 0; color: #1e293b;">${escHtmlServer(user.name)}</td></tr>
                  <tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Email</td><td style="padding: 10px 0;"><a href="mailto:${escHtmlServer(user.email)}" style="color: #2980b9;">${escHtmlServer(user.email)}</a></td></tr>
                  ${user.company ? `<tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Empresa</td><td style="padding: 10px 0; color: #1e293b;">${escHtmlServer(user.company)}</td></tr>` : ''}
                  <tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Categoría</td><td style="padding: 10px 0; color: #1e293b;">${catLabels[cat] || cat}</td></tr>
                </table>
                <div style="padding: 20px; background: white; border-radius: 8px; border: 1px solid #e2e8f0;">
                  <p style="color: #64748b; font-weight: 600; margin-bottom: 12px;">Mensaje:</p>
                  <p style="color: #1e293b; line-height: 1.6; margin: 0; white-space: pre-wrap;">${escHtmlServer(message)}</p>
                </div>
              </div>
            </div>
          `
        }).then(() => console.log('Support email sent'))
          .catch(e => console.warn('Support email failed:', e.message));
      }
    } catch (emailErr) {
      console.warn('Support email setup failed:', emailErr.message);
    }
  } catch (err) {
    console.error('Support ticket error:', err.message);
    res.status(500).json({ error: 'Error sending support request' });
  }
});

// ====== RATE LIMITING ======
const rateLimitMap = new Map();
function isRateLimited(ip, maxPerMinute = 3) {
  const now = Date.now();
  const attempts = rateLimitMap.get(ip) || [];
  const recent = attempts.filter(t => now - t < 60000);
  if (recent.length === 0) {
    rateLimitMap.delete(ip); // Clean up empty entries
  }
  if (recent.length >= maxPerMinute) return true;
  recent.push(now);
  rateLimitMap.set(ip, recent);
  return false;
}
// Periodic cleanup of stale rate limit entries
setInterval(() => {
  const now = Date.now();
  rateLimitMap.forEach((attempts, ip) => {
    const recent = attempts.filter(t => now - t < 60000);
    if (recent.length === 0) rateLimitMap.delete(ip);
    else rateLimitMap.set(ip, recent);
  });
}, 300000); // Every 5 minutes

// ====== CONTACT FORM API ======
app.post('/api/contact', async (req, res) => {
  try {
    // Rate limiting
    const clientIP = req.ip || req.connection.remoteAddress;
    if (isRateLimited(clientIP)) {
      return res.status(429).json({ error: 'Demasiadas solicitudes. Espera un momento.' });
    }

    const { name, email, company, workers, department, message } = req.body;

    // Validate required fields
    if (!name || !email) {
      return res.status(400).json({ error: 'Nombre y email son obligatorios' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Email no valido' });
    }

    // Sanitize HTML to prevent XSS in emails
    const esc = (str) => String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    const safeName = esc(name);
    const safeEmail = esc(email);
    const safeCompany = esc(company);
    const safeWorkers = esc(workers);
    const safeDepartment = esc(department);
    const safeMessage = esc(message);

    // 1. Save lead to database (primary)
    try {
      await pool.query(
        'INSERT INTO contact_leads (name, email, company, workers, department, message) VALUES ($1, $2, $3, $4, $5, $6)',
        [name, email, company || null, workers || null, department || null, message || null]
      );
    } catch (dbErr) {
      // Table might not exist yet — create it and retry
      if (dbErr.message.includes('does not exist')) {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS contact_leads (
            id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
            company VARCHAR(255), workers VARCHAR(50), department VARCHAR(255),
            message TEXT, created_at TIMESTAMP DEFAULT NOW()
          );
        `);
        await pool.query(
          'INSERT INTO contact_leads (name, email, company, workers, department, message) VALUES ($1, $2, $3, $4, $5, $6)',
          [name, email, company || null, workers || null, department || null, message || null]
        );
      } else {
        console.warn('DB insert lead failed (continuing):', dbErr.message);
      }
    }

    console.log(`Contact lead saved: ${name} <${email}> — ${company || 'N/A'}`);
    res.json({ ok: true });

    // Fire-and-forget emails (don't block response)
    try {
      if (process.env.GMAIL_APP_PASSWORD) {
        safeSendMail({
          from: `"Shiftia HUB" <${process.env.GMAIL_USER || 'highkeycvsender@gmail.com'}>`,
          to: process.env.SUPPORT_EMAIL || 'highkeycvsender@gmail.com',
          subject: `Nueva solicitud de demo — ${safeName} (${safeCompany || 'Sin empresa'})`,
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 32px;">
              <div style="background: linear-gradient(135deg, #4ecdc4, #2980b9); padding: 24px 32px; border-radius: 12px 12px 0 0;">
                <h1 style="color: white; margin: 0; font-size: 1.4rem;">Nueva solicitud de demo</h1>
              </div>
              <div style="background: #f8fafc; padding: 32px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px;">
                <table style="width: 100%; border-collapse: collapse;">
                  <tr><td style="padding: 10px 0; color: #64748b; font-weight: 600; width: 140px;">Nombre</td><td style="padding: 10px 0; color: #1e293b;">${safeName}</td></tr>
                  <tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Email</td><td style="padding: 10px 0;"><a href="mailto:${safeEmail}" style="color: #2980b9;">${safeEmail}</a></td></tr>
                  ${safeCompany ? `<tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Empresa</td><td style="padding: 10px 0; color: #1e293b;">${safeCompany}</td></tr>` : ''}
                  ${safeWorkers ? `<tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Trabajadores</td><td style="padding: 10px 0; color: #1e293b;">${safeWorkers}</td></tr>` : ''}
                  ${safeDepartment ? `<tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Departamento</td><td style="padding: 10px 0; color: #1e293b;">${safeDepartment}</td></tr>` : ''}
                </table>
                ${safeMessage ? `
                  <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e2e8f0;">
                    <p style="color: #64748b; font-weight: 600; margin-bottom: 8px;">Mensaje:</p>
                    <p style="color: #1e293b; line-height: 1.6; background: white; padding: 16px; border-radius: 8px; border: 1px solid #e2e8f0;">${safeMessage}</p>
                  </div>
                ` : ''}
                <p style="color: #94a3b8; font-size: 0.82rem; margin-top: 24px;">Enviado desde www.shiftia.es — ${new Date().toLocaleString('es-ES', { timeZone: 'Europe/Madrid' })}</p>
              </div>
            </div>
          `
        }).then(() => console.log('Contact notification email sent'))
          .catch(e => console.warn('Contact notification email failed:', e.message));

        safeSendMail({
          from: `"Shiftia" <${process.env.GMAIL_USER || 'highkeycvsender@gmail.com'}>`,
          to: email,
          subject: 'Hemos recibido tu solicitud — Shiftia',
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 32px;">
              <div style="background: linear-gradient(135deg, #4ecdc4, #2980b9); padding: 24px 32px; border-radius: 12px 12px 0 0; text-align: center;">
                <h1 style="color: white; margin: 0; font-size: 1.5rem;">Shiftia</h1>
              </div>
              <div style="background: #ffffff; padding: 32px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px;">
                <h2 style="color: #1e293b; margin-top: 0;">Hola ${safeName.split(' ')[0]},</h2>
                <p style="color: #475569; line-height: 1.7;">Hemos recibido tu solicitud correctamente. Nuestro equipo la revisara y te contactaremos en <strong>menos de 24 horas laborables</strong> con una propuesta personalizada.</p>
                <p style="color: #475569; line-height: 1.7;">Mientras tanto, si tienes cualquier duda, puedes responder a este email directamente.</p>
                <div style="margin: 28px 0; padding: 20px; background: #f0fdf9; border-radius: 8px; border-left: 4px solid #4ecdc4;">
                  <p style="color: #1e293b; margin: 0; font-weight: 600;">Lo que incluye tu demo:</p>
                  <ul style="color: #475569; line-height: 1.8; padding-left: 20px;">
                    <li>Configuracion con los datos de tu equipo</li>
                    <li>Demo en vivo del motor IA de coberturas</li>
                    <li>30 dias de prueba gratuita sin compromiso</li>
                  </ul>
                </div>
                <p style="color: #475569;">Un saludo,<br><strong>El equipo de Shiftia</strong></p>
              </div>
              <p style="text-align: center; color: #94a3b8; font-size: 0.78rem; margin-top: 20px;">www.shiftia.es</p>
            </div>
          `
        }).then(() => console.log('Contact confirmation email sent'))
          .catch(e => console.warn('Contact confirmation email failed:', e.message));
      }
    } catch (emailErr) {
      console.warn('Contact email setup failed:', emailErr.message);
    }

  } catch (err) {
    console.error('Contact form error:', err.message);
    res.status(500).json({ error: 'Error al enviar. Intentalo de nuevo.' });
  }
});

// ====== CALL BOOKING API ======
app.post('/api/booking', async (req, res) => {
  try {
    // Rate limiting
    const clientIP = req.ip || req.connection.remoteAddress;
    if (isRateLimited(clientIP)) {
      return res.status(429).json({ error: 'Demasiadas solicitudes. Espera un momento.' });
    }

    const { name, email, phone, company, workers, department, message, date, time } = req.body;

    // Validate required fields
    if (!name || !email || !phone || !date || !time) {
      return res.status(400).json({ error: 'Nombre, email, teléfono, fecha y hora son obligatorios' });
    }

    // Validate email
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Email no válido' });
    }

    // Validate date is weekday and not in the past
    const bookingDate = new Date(date + 'T00:00:00');
    const dow = bookingDate.getDay();
    if (dow === 0 || dow === 6) {
      return res.status(400).json({ error: 'Solo se puede agendar de lunes a viernes' });
    }

    // Validate time is 8-18
    const hour = parseInt(time.split(':')[0]);
    if (hour < 8 || hour > 18) {
      return res.status(400).json({ error: 'Horario disponible: 8:00 - 18:00' });
    }

    const esc = (str) => String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

    // Save booking to database
    try {
      await pool.query(
        'INSERT INTO bookings (name, email, phone, company, workers, department, message, booking_date, booking_time) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [name, email, phone, company || null, workers || null, department || null, message || null, date, time]
      );
    } catch (dbErr) {
      if (dbErr.message.includes('does not exist')) {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS bookings (
            id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
            phone VARCHAR(50) NOT NULL, company VARCHAR(255), workers VARCHAR(50),
            department VARCHAR(255), message TEXT, booking_date DATE NOT NULL,
            booking_time VARCHAR(10) NOT NULL, status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT NOW()
          );
        `);
        await pool.query(
          'INSERT INTO bookings (name, email, phone, company, workers, department, message, booking_date, booking_time) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
          [name, email, phone, company || null, workers || null, department || null, message || null, date, time]
        );
      } else {
        console.warn('DB insert booking failed:', dbErr.message);
      }
    }

    // Format date for emails
    const dayNames = ['domingo','lunes','martes','miércoles','jueves','viernes','sábado'];
    const monthNames = ['enero','febrero','marzo','abril','mayo','junio','julio','agosto','septiembre','octubre','noviembre','diciembre'];
    const prettyDate = `${dayNames[bookingDate.getDay()]} ${bookingDate.getDate()} de ${monthNames[bookingDate.getMonth()]} de ${bookingDate.getFullYear()}`;

    // Respond immediately — don't wait for emails
    console.log(`Booking: ${name} <${email}> tel:${phone} — ${date} ${time}`);
    res.json({ ok: true });

    // Fire-and-forget email notifications (don't block the response)
    try {
      if (process.env.GMAIL_APP_PASSWORD) {
        // 1. Notification to Diego
        safeSendMail({
          from: `"Shiftia Booking" <${process.env.GMAIL_USER || 'highkeycvsender@gmail.com'}>`,
          to: process.env.SUPPORT_EMAIL || 'highkeycvsender@gmail.com',
          subject: `📞 Nueva llamada agendada — ${esc(name)} (${esc(company || 'N/A')}) — ${prettyDate} ${time}h`,
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
              <div style="background: linear-gradient(135deg, #4ecdc4, #2980b9); padding: 24px 32px; border-radius: 12px 12px 0 0;">
                <h1 style="color: white; margin: 0; font-size: 1.3rem;">📞 Llamada agendada</h1>
              </div>
              <div style="background: #f8fafc; padding: 32px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px;">
                <div style="background: #f0fdf9; padding: 20px; border-radius: 10px; border-left: 4px solid #4ecdc4; margin-bottom: 24px;">
                  <p style="margin: 0; font-size: 1.1rem; font-weight: 700; color: #1e293b;">📅 ${prettyDate} a las ${time}h</p>
                </div>
                <table style="width: 100%; border-collapse: collapse;">
                  <tr><td style="padding: 10px 0; color: #64748b; font-weight: 600; width: 130px;">Nombre</td><td style="padding: 10px 0; color: #1e293b;">${esc(name)}</td></tr>
                  <tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Email</td><td style="padding: 10px 0;"><a href="mailto:${esc(email)}" style="color: #2980b9;">${esc(email)}</a></td></tr>
                  <tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Teléfono</td><td style="padding: 10px 0; color: #1e293b; font-weight: 700;"><a href="tel:${esc(phone)}" style="color: #2980b9;">${esc(phone)}</a></td></tr>
                  ${company ? `<tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Empresa</td><td style="padding: 10px 0; color: #1e293b;">${esc(company)}</td></tr>` : ''}
                  ${workers ? `<tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Trabajadores</td><td style="padding: 10px 0; color: #1e293b;">${esc(workers)}</td></tr>` : ''}
                  ${department ? `<tr><td style="padding: 10px 0; color: #64748b; font-weight: 600;">Departamento</td><td style="padding: 10px 0; color: #1e293b;">${esc(department)}</td></tr>` : ''}
                </table>
                ${message ? `<div style="margin-top: 20px; padding: 16px; background: white; border-radius: 8px; border: 1px solid #e2e8f0;"><p style="color: #64748b; font-weight: 600; margin: 0 0 8px 0;">Mensaje:</p><p style="color: #1e293b; line-height: 1.6; margin: 0;">${esc(message)}</p></div>` : ''}
                <p style="color: #94a3b8; font-size: 0.82rem; margin-top: 24px;">Reservado desde shiftia.es — ${new Date().toLocaleString('es-ES', { timeZone: 'Europe/Madrid' })}</p>
              </div>
            </div>
          `
        }).then(() => console.log('Booking notification email sent'))
          .catch(e => console.warn('Booking notification email failed:', e.message));

        // 2. Confirmation to client
        safeSendMail({
          from: `"Shiftia" <${process.env.GMAIL_USER || 'highkeycvsender@gmail.com'}>`,
          to: email,
          subject: `Llamada confirmada — ${prettyDate} a las ${time}h — Shiftia`,
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
              <div style="background: linear-gradient(135deg, #4ecdc4, #2980b9); padding: 24px 32px; border-radius: 12px 12px 0 0; text-align: center;">
                <h1 style="color: white; margin: 0; font-size: 1.5rem;">Shiftia</h1>
              </div>
              <div style="background: #ffffff; padding: 32px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px;">
                <h2 style="color: #1e293b; margin-top: 0;">Hola ${esc(name).split(' ')[0]},</h2>
                <p style="color: #475569; line-height: 1.7;">Tu llamada ha sido agendada correctamente. Aquí tienes los detalles:</p>
                <div style="margin: 24px 0; padding: 24px; background: linear-gradient(135deg, rgba(78,205,196,0.08), rgba(41,128,185,0.08)); border-radius: 12px; border: 1px solid rgba(78,205,196,0.2); text-align: center;">
                  <p style="margin: 0 0 4px 0; font-size: 0.85rem; color: #64748b;">Fecha y hora</p>
                  <p style="margin: 0; font-size: 1.25rem; font-weight: 700; color: #2980b9;">${prettyDate}</p>
                  <p style="margin: 4px 0 0 0; font-size: 1.5rem; font-weight: 800; color: #4ecdc4;">${time}h</p>
                </div>
                <p style="color: #475569; line-height: 1.7;">Nos pondremos en contacto contigo al teléfono <strong>${esc(phone)}</strong> o por email para coordinar los detalles de la reunión.</p>
                <p style="color: #475569; line-height: 1.7;">Si necesitas cancelar o cambiar la hora, responde a este email.</p>
                <p style="color: #475569; margin-top: 24px;">Un saludo,<br><strong>El equipo de Shiftia</strong></p>
              </div>
              <p style="text-align: center; color: #94a3b8; font-size: 0.78rem; margin-top: 20px;">www.shiftia.es</p>
            </div>
          `
        }).then(() => console.log('Booking confirmation email sent to', email))
          .catch(e => console.warn('Booking confirmation email failed:', e.message));
      }
    } catch (emailErr) {
      console.warn('Booking email setup failed:', emailErr.message);
    }

  } catch (err) {
    console.error('Booking error:', err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Error al agendar. Inténtalo de nuevo.' });
    }
  }
});

// ====== STATIC ROUTES ======
// Serve login.html
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve dashboard.html
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Serve docs.html
app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

// Coverage notification endpoint
// HTML escape helper for emails
function escHtmlServer(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

// Email validation helper
function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

app.post('/api/notify', authMiddleware, async (req, res) => {
  try {
    const { workerEmail, workerName, shift, date, absentName, acceptedBy } = req.body;

    // Validate email
    if (!isValidEmail(workerEmail)) {
      return res.status(400).json({ error: 'Email inválido' });
    }

    // Sanitize all inputs
    const safeWorkerName = escHtmlServer(String(workerName || '').slice(0, 200));
    const safeAbsentName = escHtmlServer(String(absentName || '').slice(0, 200));
    const safeShift = escHtmlServer(String(shift || '').slice(0, 50));
    const safeDate = escHtmlServer(String(date || '').slice(0, 50));
    const safeAcceptedBy = escHtmlServer(String(acceptedBy || '').slice(0, 200));

    // Configure email (console.log fallback if SMTP not configured)
    const hasEmail = process.env.SMTP_HOST;

    if (hasEmail) {
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });

      const mailOptions = {
        from: process.env.SMTP_FROM || 'noreply@hospital.es',
        to: workerEmail,
        subject: 'Asignación de Cobertura — Fundación Hospital de Jove',
        html: `
          <h2>Hola ${safeWorkerName},</h2>
          <p>Se te ha asignado una cobertura por ausencia.</p>
          <table style="width:100%;border-collapse:collapse;margin:20px 0;">
            <tr style="background:#f5f5f5;">
              <td style="padding:10px;border:1px solid #ddd;"><strong>Trabajador Ausente</strong></td>
              <td style="padding:10px;border:1px solid #ddd;">${safeAbsentName}</td>
            </tr>
            <tr>
              <td style="padding:10px;border:1px solid #ddd;"><strong>Turno</strong></td>
              <td style="padding:10px;border:1px solid #ddd;">${safeShift}</td>
            </tr>
            <tr style="background:#f5f5f5;">
              <td style="padding:10px;border:1px solid #ddd;"><strong>Fecha</strong></td>
              <td style="padding:10px;border:1px solid #ddd;">${safeDate}</td>
            </tr>
            <tr>
              <td style="padding:10px;border:1px solid #ddd;"><strong>Aprobado por</strong></td>
              <td style="padding:10px;border:1px solid #ddd;">${safeAcceptedBy}</td>
            </tr>
          </table>
          <p style="color:#666;font-size:12px;">Mensaje generado automáticamente por Shiftia v5.3</p>
        `
      };

      await safeSendMail(mailOptions);
      res.json({ success: true, message: 'Email enviado correctamente' });
    } else {
      console.log('[Email Notification] To:', workerEmail, 'Coverage:', absentName, '→', shift, 'on', date);
      res.json({ success: true, message: 'Notificación registrada (sin SMTP configurado)' });
    }
  } catch (err) {
    console.error('[Notify Error]', err.message);
    res.status(500).json({ error: 'Error al enviar notificación' });
  }
});

// ====== WORKER MOBILE API ======
// GET /api/my-shifts?worker=Name — Get shifts for a specific worker (read-only, for workers)
app.get('/api/my-shifts', authMiddleware, async (req, res) => {
  try {
    const workerName = (req.query.worker || '').slice(0, 200);
    const month = Math.max(0, Math.min(11, parseInt(req.query.month, 10) || new Date().getMonth()));
    const year = Math.max(2020, Math.min(2100, parseInt(req.query.year, 10) || new Date().getFullYear()));

    if (!workerName) {
      return res.status(400).json({ error: 'worker parameter is required' });
    }

    const result = await pool.query(
      'SELECT data FROM schedule_data WHERE user_id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.json({ shifts: [], worker: workerName });
    }

    const data = result.rows[0].data;
    const scheduleKey = `${year}-${month}`;
    const schedule = data.scheduleData && data.scheduleData[scheduleKey];

    if (!schedule) {
      return res.json({ shifts: [], worker: workerName, month, year });
    }

    // Find the worker by name
    const workers = data.workerMeta || [];
    const worker = workers.find(w => w.name && w.name.toLowerCase().includes(workerName.toLowerCase()));

    if (!worker) {
      return res.json({ shifts: [], worker: workerName, error: 'Worker not found' });
    }

    const workerSchedule = schedule[worker.id] || [];
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const shifts = [];

    for (let d = 0; d < daysInMonth; d++) {
      const date = new Date(year, month, d + 1);
      shifts.push({
        day: d + 1,
        date: date.toISOString().split('T')[0],
        dayName: ['Dom','Lun','Mar','Mie','Jue','Vie','Sab'][date.getDay()],
        shift: workerSchedule[d] || '',
        isWeekend: date.getDay() === 0 || date.getDay() === 6
      });
    }

    res.json({
      worker: worker.name,
      type: worker.type,
      month,
      year,
      shifts,
      totalShifts: shifts.filter(s => ['M','MR','M7H','M6R','M55','T','N'].includes(s.shift)).length,
      totalNights: shifts.filter(s => s.shift === 'N').length,
      totalRest: shifts.filter(s => s.shift === 'D').length
    });
  } catch (err) {
    console.error('My shifts error:', err.message);
    res.status(500).json({ error: 'Error loading shifts' });
  }
});

// GET /api/workers — List all workers (names + types)
app.get('/api/workers', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT data FROM schedule_data WHERE user_id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) return res.json({ workers: [] });

    const workers = result.rows[0].data.workerMeta || [];
    res.json({
      workers: workers.map(w => ({ id: w.id, name: w.name, type: w.type, area: w.area }))
    });
  } catch (err) {
    console.error('Workers list error:', err.message);
    res.status(500).json({ error: 'Error loading workers' });
  }
});

// ====== AUDIT LOG ROUTES ======
// GET /api/audit — Get recent audit entries
app.get('/api/audit', authMiddleware, async (req, res) => {
  try {
    const parsedLimit = parseInt(req.query.limit, 10);
    const limit = Math.min(Math.max(1, isNaN(parsedLimit) ? 50 : parsedLimit), 200);
    const result = await pool.query(
      'SELECT id, action, details, ip_address, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2',
      [req.user.id, limit]
    );
    res.json({ logs: result.rows });
  } catch (err) {
    console.error('Audit log error:', err.message);
    res.status(500).json({ error: 'Error loading audit log' });
  }
});

// ====== BACKUP ROUTES ======
// GET /api/backups — List backups
app.get('/api/backups', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, backup_type, created_at, octet_length(data::text) as size_bytes FROM schedule_backups WHERE user_id = $1 ORDER BY created_at DESC LIMIT 30",
      [req.user.id]
    );
    res.json({ backups: result.rows });
  } catch (err) {
    console.error('Backups list error:', err.message);
    res.status(500).json({ error: 'Error loading backups' });
  }
});

// POST /api/backups — Create manual backup
app.post('/api/backups', authMiddleware, async (req, res) => {
  try {
    const current = await pool.query('SELECT data FROM schedule_data WHERE user_id = $1', [req.user.id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'No data to backup' });

    await pool.query(
      'INSERT INTO schedule_backups (user_id, data, backup_type) VALUES ($1, $2, $3)',
      [req.user.id, JSON.stringify(current.rows[0].data), 'manual']
    );

    logAudit(req.user.id, 'manual_backup', {}, req.ip);
    res.json({ success: true });
  } catch (err) {
    console.error('Create backup error:', err.message);
    res.status(500).json({ error: 'Error creating backup' });
  }
});

// POST /api/backups/:id/restore — Restore from a backup
app.post('/api/backups/:id/restore', authMiddleware, async (req, res) => {
  try {
    const backupId = parseInt(req.params.id, 10);
    if (isNaN(backupId) || backupId <= 0) {
      return res.status(400).json({ error: 'Invalid backup ID' });
    }
    const backup = await pool.query(
      'SELECT data FROM schedule_backups WHERE id = $1 AND user_id = $2',
      [backupId, req.user.id]
    );
    if (backup.rows.length === 0) return res.status(404).json({ error: 'Backup not found' });

    // Create a backup of current state before restoring
    const current = await pool.query('SELECT data FROM schedule_data WHERE user_id = $1', [req.user.id]);
    if (current.rows.length > 0) {
      await pool.query(
        'INSERT INTO schedule_backups (user_id, data, backup_type) VALUES ($1, $2, $3)',
        [req.user.id, JSON.stringify(current.rows[0].data), 'pre_restore']
      );
    }

    // Restore
    await pool.query(`
      INSERT INTO schedule_data (user_id, data, updated_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (user_id) DO UPDATE SET data = $2, updated_at = NOW()
    `, [req.user.id, JSON.stringify(backup.rows[0].data)]);

    logAudit(req.user.id, 'restore_backup', { backup_id: backupId }, req.ip);
    res.json({ success: true });
  } catch (err) {
    console.error('Restore backup error:', err.message);
    res.status(500).json({ error: 'Error restoring backup' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    version: PKG_VERSION,
    auth: 'enabled',
    websocket: true,
    backups: true,
    db: dbAvailable
  });
});

// Version endpoint público — para verificar deploys sin entrar en panel
app.get('/version', (req, res) => {
  res.type('text/plain').send(
    `Shiftia Director v${PKG_VERSION}\n` +
    `NODE_ENV=${process.env.NODE_ENV || 'development'}\n` +
    `DB=${dbAvailable ? 'connected' : 'offline'}\n` +
    `Boot=${new Date().toISOString()}\n`
  );
});

// 404 JSON para cualquier /api/* no manejado (mejor que el SPA fallback)
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found', path: req.path });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global error handler — no filtra stack traces en producción
app.use((err, req, res, next) => {
  console.error('[GLOBAL ERROR]', err.message, IS_PRODUCTION ? '' : err.stack);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({
    error: IS_PRODUCTION ? 'Error interno del servidor' : err.message
  });
});

// ====== DAILY SUMMARY EMAIL (7:00 AM) ======
async function sendDailySummary() {
  try {
    const now = new Date();
    const dayNames = ['Domingo','Lunes','Martes','Miércoles','Jueves','Viernes','Sábado'];
    const monthNames = ['Enero','Febrero','Marzo','Abril','Mayo','Junio','Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];

    // Get all users with data
    const users = await pool.query('SELECT id, email, name FROM users WHERE plan_status = $1', ['active']);

    for (const user of users.rows) {
      const dataRes = await pool.query('SELECT data FROM schedule_data WHERE user_id = $1', [user.id]);
      if (!dataRes.rows.length) continue;

      const data = dataRes.rows[0].data;
      const key = `${now.getFullYear()}-${now.getMonth()}`;
      const sch = data.scheduleData?.[key] || {};

      // Count shifts today
      const dayIdx = now.getDate() - 1;
      const shifts = { M: [], T: [], N: [] };
      const absences = [];

      const workersData = data.workers || [];
      workersData.forEach(w => {
        const s = sch[w.id]?.[dayIdx] || '';
        if (shifts[s]) shifts[s].push(escHtmlServer(w.name));
        else if (['VAC','BAJ','FOR','LAC','MTC','HS','CAA','INT'].includes(s)) {
          absences.push(`${escHtmlServer(w.name)} (${s})`);
        }
      });

      const html = `
        <div style="font-family:'DM Sans',sans-serif;max-width:500px;margin:0 auto;padding:24px;">
          <div style="text-align:center;margin-bottom:20px;">
            <h2 style="color:#2e8b7a;margin:0;">Shiftia — Resumen Diario</h2>
            <p style="color:#888;font-size:14px;margin:4px 0;">${dayNames[now.getDay()]}, ${now.getDate()} de ${monthNames[now.getMonth()]} ${now.getFullYear()}</p>
          </div>
          <div style="background:#f8f8f8;border-radius:12px;padding:16px;margin-bottom:12px;">
            <h3 style="margin:0 0 8px;font-size:14px;color:#333;">☀️ Mañana</h3>
            <p style="margin:0;color:#555;">${shifts.M.join(', ') || 'Sin asignar'}</p>
          </div>
          <div style="background:#f8f8f8;border-radius:12px;padding:16px;margin-bottom:12px;">
            <h3 style="margin:0 0 8px;font-size:14px;color:#333;">🌅 Tarde</h3>
            <p style="margin:0;color:#555;">${shifts.T.join(', ') || 'Sin asignar'}</p>
          </div>
          <div style="background:#f8f8f8;border-radius:12px;padding:16px;margin-bottom:12px;">
            <h3 style="margin:0 0 8px;font-size:14px;color:#333;">🌙 Noche</h3>
            <p style="margin:0;color:#555;">${shifts.N.join(', ') || 'Sin asignar'}</p>
          </div>
          ${absences.length > 0 ? `
          <div style="background:#fff3f3;border-radius:12px;padding:16px;margin-bottom:12px;">
            <h3 style="margin:0 0 8px;font-size:14px;color:#cc4444;">⚠ Ausencias (${absences.length})</h3>
            <p style="margin:0;color:#555;">${absences.join(', ')}</p>
          </div>` : ''}
          <p style="text-align:center;font-size:11px;color:#aaa;margin-top:20px;">
            Enviado automáticamente por Shiftia SARA · <a href="${process.env.RAILWAY_PUBLIC_DOMAIN ? 'https://' + process.env.RAILWAY_PUBLIC_DOMAIN : 'http://localhost:3000'}" style="color:#2e8b7a;">Abrir app</a>
          </p>
        </div>
      `;

      try {
        await safeSendMail({
          from: `"Shiftia SARA" <${process.env.GMAIL_USER || 'highkeycvsender@gmail.com'}>`,
          to: user.email,
          subject: `📋 Turnos ${dayNames[now.getDay()]} ${now.getDate()}/${now.getMonth() + 1} — Shiftia`,
          html
        });
        console.log(`[Email] Daily summary sent to ${user.email}`);
      } catch (emailErr) {
        console.warn(`[Email] Failed to send to ${user.email}:`, emailErr.message);
      }
    }
  } catch (err) {
    console.warn('[Email] Daily summary error:', err.message);
  }
}

// Schedule daily at 7:00 AM (Spain timezone)
function scheduleDailySummary() {
  const now = new Date();
  const target = new Date(now);
  target.setHours(7, 0, 0, 0);
  if (now >= target) target.setDate(target.getDate() + 1);
  const delay = target - now;
  setTimeout(() => {
    sendDailySummary();
    setInterval(sendDailySummary, 24 * 60 * 60 * 1000);
  }, delay);
  console.log(`[Email] Daily summary scheduled for ${target.toISOString()} (in ${Math.round(delay / 60000)} min)`);
}

// ====== SERVER STARTUP ======
async function startServer() {
  try {
    // Initialize database
    await initializeDatabase();

    server.listen(PORT, () => {
      console.log(`Shiftia Director running on port ${PORT}`);
      console.log('Authentication: enabled');
      console.log('WebSocket: enabled (/ws)');
      console.log('Auto-backups: enabled');
      console.log('Audit logs: enabled');
      console.log('Worker API: enabled (/api/my-shifts)');
      console.log('Daily email summary: enabled');
      scheduleDailySummary();
    });
  } catch (err) {
    console.error('Failed to start server:', err.message);
    process.exit(1);
  }
}

startServer();
