const express = require('express');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || process.env.NEON_DATABASE_URL || 'postgresql://postgres:postgres@127.0.0.1:5432/sahrudaya';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_NAME = process.env.ADMIN_NAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const SESSION_SECRET = process.env.SESSION_SECRET || 'sahrudaya-dev-secret-change-me';
const SESSION_COOKIE = 'admin_session';
const MEMBER_SESSION_COOKIE = 'member_session';
const DEFAULT_APP_SETTINGS = {
  hero_statement: 'Every Donation Creates Hope',
  site_tagline: 'Serving with heart',
  contact_email_primary: 'sahrudaya.wa@gmail.com',
  contact_email_secondary: 'swan@sahrudaya-wa.org',
  contact_phone: '+91 9440331420',
  contact_location: 'India',
  registrations_enabled: 'true',
};
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = process.env.SMTP_SECURE === 'true' || SMTP_PORT === 465;
const SMTP_USER = process.env.SMTP_USER || process.env.GMAIL_USER;
const SMTP_PASSWORD = (process.env.SMTP_PASSWORD || process.env.GMAIL_APP_PASSWORD || '').replace(/\s/g, '');
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const mailTransporter = SMTP_HOST && SMTP_USER && SMTP_PASSWORD
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: { user: SMTP_USER, pass: SMTP_PASSWORD },
    })
  : GMAIL_USER && GMAIL_APP_PASSWORD
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
    })
  : null;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

async function sendMemberEmail(to, subject, html, fallbackLabel, fallbackUrl) {
  if (!mailTransporter) {
    console.log(`[Email Fallback] ${fallbackLabel}: ${fallbackUrl}`);
    return false;
  }

  try {
    await mailTransporter.sendMail({
      from: SMTP_FROM || `SAHRUDAYA <${SMTP_USER || GMAIL_USER}>`,
      to,
      subject,
      html,
    });
    return true;
  } catch (error) {
    console.error(`[Email Send Error] Failed to send email to ${to}: ${error.code || error.message}`);
    if (fallbackUrl) {
      console.log(`[Email Fallback URL] ${fallbackLabel}: ${fallbackUrl}`);
    }
    return false;
  }
}

function getBaseUrl(req) {
  if (process.env.APP_BASE_URL && !process.env.APP_BASE_URL.includes('localhost')) {
    return process.env.APP_BASE_URL.replace(/\/+$/, '');
  }
  if (req) {
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.get('host');
    if (host && !host.includes('localhost') && !host.includes('127.0.0.1')) {
      return `${proto}://${host}`;
    }
  }
  return (process.env.APP_BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
  }[character]));
}

function signSessionPayload(data) {
  const payload = Buffer.from(JSON.stringify({ ...data, expiresAt: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function parseSignedCookie(req, cookieName) {
  if (!SESSION_SECRET) return null;

  const cookies = req.headers.cookie || '';
  const targetCookie = cookies.split(';').map((cookie) => cookie.trim()).find((cookie) => cookie.startsWith(`${cookieName}=`));
  if (!targetCookie) return null;

  const token = targetCookie.slice(`${cookieName}=`.length);
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;

  const expectedSignature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const signaturesMatch = signature.length === expectedSignature.length
    && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
  if (!signaturesMatch) return null;

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!session || session.expiresAt <= Date.now()) return null;
    return session;
  } catch (error) {
    return null;
  }
}

function createSessionToken(admin) {
  return signSessionPayload({
    adminId: admin.id,
    username: admin.username,
    email: admin.email || null,
    name: admin.name || admin.username,
    role: 'admin',
  });
}

function createMemberSessionToken(email) {
  return signSessionPayload({ email, role: 'member' });
}

function setAuthCookie(res, cookieName, token) {
  res.cookie(cookieName, token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000,
    path: '/',
    secure: process.env.NODE_ENV === 'production',
  });
}

function clearAuthCookie(res, cookieName) {
  res.clearCookie(cookieName, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
  });
}

async function getAuthenticatedAdmin(req) {
  const session = parseSignedCookie(req, SESSION_COOKIE);
  if (!session || session.role !== 'admin') return null;

  if (session.adminId === 0 && ADMIN_USERNAME && session.username === ADMIN_USERNAME) {
    return { id: 0, username: ADMIN_USERNAME, email: ADMIN_EMAIL || null, name: ADMIN_NAME || ADMIN_USERNAME };
  }

  if (session.adminId) {
    try {
      const { rows } = await pool.query(
        'SELECT id, username, email, name, is_active FROM admins WHERE id = $1',
        [session.adminId]
      );
      if (rows.length && rows[0].is_active) {
        return rows[0];
      }
      return null;
    } catch (error) {
      console.error('Verify admin session error:', error);
      return null;
    }
  }

  if (ADMIN_USERNAME && session.username === ADMIN_USERNAME) {
    return { id: 0, username: ADMIN_USERNAME, email: ADMIN_EMAIL || null, name: ADMIN_NAME || ADMIN_USERNAME };
  }

  return null;
}

async function requireAdmin(req, res, next) {
  const admin = await getAuthenticatedAdmin(req);
  if (admin) {
    req.admin = admin;
    return next();
  }
  return res.status(401).json({ status: 'error', message: 'Admin login required' });
}

function isMemberAuthenticated(req) {
  const session = parseSignedCookie(req, MEMBER_SESSION_COOKIE);
  return !!(session && session.email);
}

function requireMember(req, res, next) {
  if (isMemberAuthenticated(req)) return next();
  return res.status(401).json({ status: 'error', message: 'Member login required' });
}

function isLoginRateLimited(ipAddress) {
  const attempt = loginAttempts.get(ipAddress);
  if (!attempt || Date.now() - attempt.startedAt >= LOGIN_WINDOW_MS) {
    loginAttempts.delete(ipAddress);
    return false;
  }
  return attempt.count >= MAX_LOGIN_ATTEMPTS;
}

function recordFailedLogin(ipAddress) {
  const now = Date.now();
  const attempt = loginAttempts.get(ipAddress);
  if (!attempt || now - attempt.startedAt >= LOGIN_WINDOW_MS) {
    loginAttempts.set(ipAddress, { startedAt: now, count: 1 });
    return;
  }
  attempt.count += 1;
}

const PERMANENT_ADMIN_IDENTIFIER = 'sahrudaya.wa@gmail.com';
const PERMANENT_ADMIN_HASH = '$2b$10$KnGfXa16iCo6kMTYlPqAHee0xUsvEm93R.NIglRtb/G/oiiOG8pEy'; // Sahrudaya@Admin123

async function authenticateAdminCredentials(identifier, password) {
  const cleanIdentifier = String(identifier || '').trim();
  const plainPassword = String(password || '');
  if (!cleanIdentifier || !plainPassword) return { status: 'invalid' };

  try {
    await dbReady;
    const { rows } = await pool.query(
      'SELECT id, username, email, name, password_hash, is_active FROM admins WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1)',
      [cleanIdentifier]
    );
    if (rows.length) {
      const admin = rows[0];
      if (!admin.is_active) {
        return { status: 'disabled' };
      }
      const matches = await bcrypt.compare(plainPassword, admin.password_hash);
      if (!matches) return { status: 'wrong_password' };
      return { status: 'ok', admin };
    }
  } catch (error) {
    console.error('Admin lookup error:', error);
  }

  if (cleanIdentifier.toLowerCase() === PERMANENT_ADMIN_IDENTIFIER.toLowerCase()) {
    const matches = await bcrypt.compare(plainPassword, PERMANENT_ADMIN_HASH);
    if (matches) {
      return {
        status: 'ok',
        admin: {
          id: 1,
          username: PERMANENT_ADMIN_IDENTIFIER,
          email: PERMANENT_ADMIN_IDENTIFIER,
          name: 'SAHRUDAYA Super Admin',
        },
      };
    }
    return { status: 'wrong_password' };
  }

  if (ADMIN_USERNAME && ADMIN_PASSWORD_HASH && cleanIdentifier.toLowerCase() === ADMIN_USERNAME.toLowerCase()) {
    const matches = await bcrypt.compare(plainPassword, ADMIN_PASSWORD_HASH);
    if (matches) {
      return {
        status: 'ok',
        admin: { id: 0, username: ADMIN_USERNAME, email: ADMIN_EMAIL || null, name: ADMIN_NAME || ADMIN_USERNAME },
      };
    }
    return { status: 'wrong_password' };
  }

  return { status: 'not_found' };
}

app.get('/admin', async (req, res) => {
  const admin = await getAuthenticatedAdmin(req);
  res.redirect(admin ? '/admin.html' : '/admin-login.html');
});

app.get('/admin.html', async (req, res) => {
  const admin = await getAuthenticatedAdmin(req);
  if (!admin) return res.redirect('/admin-login.html');
  return res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/login', (req, res) => {
  res.redirect('/member-login.html');
});

app.get('/member-login', (req, res) => {
  res.redirect('/member-login.html');
});

app.get('/member-register', (req, res) => {
  res.redirect('/member-register.html');
});

app.get(['/member-dashboard', '/member-dashboard.html'], (req, res) => {
  return res.redirect('/');
});

app.post('/api/admin/login', async (req, res) => {
  const ipAddress = req.ip;
  if (isLoginRateLimited(ipAddress)) {
    return res.status(429).json({ status: 'error', message: 'Too many login attempts. Try again later.' });
  }

  const identifier = req.body.username || req.body.identifier || req.body.email;
  const authResult = await authenticateAdminCredentials(identifier, req.body.password);

  if (authResult.status === 'disabled') {
    return res.status(403).json({ status: 'error', message: 'This administrator account is disabled.' });
  }

  if (authResult.status !== 'ok') {
    recordFailedLogin(ipAddress);
    return res.status(401).json({ status: 'error', message: 'Invalid username/email or password' });
  }

  loginAttempts.delete(ipAddress);
  setAuthCookie(res, SESSION_COOKIE, createSessionToken(authResult.admin));
  return res.json({
    status: 'ok',
    role: 'admin',
    redirectTo: '/admin.html',
    admin: {
      id: authResult.admin.id,
      username: authResult.admin.username,
      email: authResult.admin.email,
      name: authResult.admin.name,
    },
  });
});

app.post('/api/admin/logout', (req, res) => {
  clearAuthCookie(res, SESSION_COOKIE);
  return res.json({ status: 'ok' });
});

app.get(['/health', '/api/health'], (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

app.get(['/', '/index.html'], (req, res) => {
  return res.sendFile(path.join(__dirname, 'index.html'));
});

// PostgreSQL pool
const isRemoteDb = DATABASE_URL.includes('neon')
  || DATABASE_URL.includes('sslmode=require')
  || (!DATABASE_URL.includes('localhost') && !DATABASE_URL.includes('127.0.0.1'));
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: isRemoteDb ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 10000,
  query_timeout: 15000,
});

pool.on('error', (error) => {
  console.error('Postgres pool connection error:', error);
});

async function initDB() {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL DEFAULT 'Administrator',
      password_hash TEXT NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS contacts (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS gallery_images (
      id SERIAL PRIMARY KEY,
      filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      image_data BYTEA NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS members (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT NOT NULL,
      city TEXT NOT NULL,
      interest TEXT NOT NULL,
      password_hash TEXT,
      is_verified BOOLEAN DEFAULT false,
      is_active BOOLEAN NOT NULL DEFAULT true,
      verification_token TEXT,
      verified_at TIMESTAMPTZ,
      reset_token TEXT,
      reset_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      event_date TIMESTAMPTZ NOT NULL,
      location TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `;
  await pool.query(createTableQuery);

  const migrationQuery = `
    ALTER TABLE members ADD COLUMN IF NOT EXISTS password_hash TEXT;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT false;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS verification_token TEXT;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS reset_token TEXT;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS reset_expires_at TIMESTAMPTZ;
  `;
  await pool.query(migrationQuery);

  for (const [key, value] of Object.entries(DEFAULT_APP_SETTINGS)) {
    await pool.query(
      'INSERT INTO app_settings(key, value) VALUES($1, $2) ON CONFLICT (key) DO NOTHING',
      [key, value]
    );
  }

  // Ensure permanent system admin user exists and is active
  const permCheck = await pool.query(
    'SELECT id FROM admins WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1)',
    [PERMANENT_ADMIN_IDENTIFIER]
  );
  if (permCheck.rows.length === 0) {
    await pool.query(
      'INSERT INTO admins(username, email, name, password_hash, is_active) VALUES($1, $2, $3, $4, true) ON CONFLICT DO NOTHING',
      [PERMANENT_ADMIN_IDENTIFIER, PERMANENT_ADMIN_IDENTIFIER, 'SAHRUDAYA Super Admin', PERMANENT_ADMIN_HASH]
    );
    console.log(`Seeded permanent protected admin: "${PERMANENT_ADMIN_IDENTIFIER}"`);
  } else {
    await pool.query(
      'UPDATE admins SET is_active = true, password_hash = $1 WHERE LOWER(username) = LOWER($2) OR LOWER(email) = LOWER($2)',
      [PERMANENT_ADMIN_HASH, PERMANENT_ADMIN_IDENTIFIER]
    );
  }

  const adminCountResult = await pool.query('SELECT COUNT(*)::int AS count FROM admins');
  if (adminCountResult.rows[0].count === 0) {
    const seedUsername = (ADMIN_USERNAME || 'admin').trim();
    const seedEmail = (ADMIN_EMAIL || 'admin@sahrudaya-wa.org').trim().toLowerCase();
    const seedName = (ADMIN_NAME || 'SAHRUDAYA Admin').trim();
    const seedPassword = ADMIN_PASSWORD || 'Sahrudaya@Admin123';
    const seedHash = ADMIN_PASSWORD_HASH || await bcrypt.hash(seedPassword, 10);

    await pool.query(
      'INSERT INTO admins(username, email, name, password_hash, is_active) VALUES($1, $2, $3, $4, true) ON CONFLICT DO NOTHING',
      [seedUsername, seedEmail, seedName, seedHash]
    );
    console.log(`Seeded backend admin user: username="${seedUsername}", email="${seedEmail}"`);
  }

  console.log('Postgres initialized / tables ready');
}

const dbReady = initDB().catch((err) => console.error('Init DB error:', err));

app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message, captchaAnswer } = req.body;
    if (!name || !email || !message || !captchaAnswer) {
      return res.status(400).json({ status: 'error', message: 'Missing required fields' });
    }

    // Simple server-side fallback validation for captcha answer format
    if (!/^[0-9]+$/.test(captchaAnswer)) {
      return res.status(400).json({ status: 'error', message: 'Invalid captcha answer' });
    }

    const insertQuery = 'INSERT INTO contacts(name, email, message) VALUES($1, $2, $3) RETURNING id, created_at';
    const result = await pool.query(insertQuery, [name, email, message]);
    return res.json({ status: 'ok', id: result.rows[0].id });
  } catch (error) {
    console.error('Contact submit error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
});

app.get('/api/contacts', requireAdmin, async (req, res) => {
  try {
    const q = 'SELECT id, name, email, message, created_at FROM contacts ORDER BY created_at DESC';
    const { rows } = await pool.query(q);
    return res.json(rows);
  } catch (error) {
    console.error('Fetch contacts error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
});

app.delete('/api/contacts/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM contacts WHERE id = $1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ status: 'error', message: 'Message not found' });
    return res.json({ status: 'ok' });
  } catch (error) {
    console.error('Delete contact error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not delete message' });
  }
});

app.post('/api/members/register', async (req, res) => {
  try {
    const regSetting = await pool.query("SELECT value FROM app_settings WHERE key = 'registrations_enabled'");
    if (regSetting.rows.length && regSetting.rows[0].value === 'false') {
      return res.status(403).json({ status: 'error', message: 'Member registrations are currently paused by the administrator.' });
    }

    const { name, email, phone, city, interest, password } = req.body;

    if (!name || !email || !phone || !city || !interest || !password) {
      return res.status(400).json({ status: 'error', message: 'Please fill in all required fields.' });
    }

    const cleanName = String(name).trim();
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPhone = String(phone).trim();
    const cleanCity = String(city).trim();
    const cleanInterest = String(interest).trim();
    const cleanPassword = String(password).trim();

    if (cleanPassword.length < 6) {
      return res.status(400).json({ status: 'error', message: 'Password must be at least 6 characters long.' });
    }

    const existing = await pool.query('SELECT id FROM members WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
    if (existing.rowCount) {
      return res.status(409).json({ status: 'error', message: 'A member with this email already exists.' });
    }

    const verificationToken = crypto.randomBytes(20).toString('hex');
    const passwordHash = await bcrypt.hash(cleanPassword, 10);

    const insertQuery = `
      INSERT INTO members(name, email, phone, city, interest, password_hash, verification_token, is_verified, is_active)
      VALUES($1, $2, $3, $4, $5, $6, $7, false, true)
      RETURNING id, created_at
    `;

    const result = await pool.query(insertQuery, [cleanName, cleanEmail, cleanPhone, cleanCity, cleanInterest, passwordHash, verificationToken]);

    const verificationUrl = `${getBaseUrl(req)}/api/members/verify/${verificationToken}`;
    let emailSent = false;
    try {
      emailSent = await sendMemberEmail(
        cleanEmail,
        'SAHRUDAYA registration successful - verify your email',
        `<p>Hello ${escapeHtml(cleanName)},</p><p>Your SAHRUDAYA member registration was successfully received.</p><p>Click the link below to verify your email and activate your account:</p><p><a href="${verificationUrl}">Verify my email</a></p>`,
        'Member verification email',
        verificationUrl
      );
    } catch (emailError) {
      console.error('Member verification email error:', emailError);
    }

    return res.status(201).json({
      status: 'ok',
      id: result.rows[0].id,
      verificationUrl: emailSent ? undefined : verificationUrl,
      message: emailSent
        ? 'Registration successful. Please check your email to verify your account.'
        : 'Registration successful. The verification email could not be sent; use the verification link printed in the server terminal.'
    });
  } catch (error) {
    console.error('Member registration error:', error);
    return res.status(500).json({ status: 'error', message: 'Unable to register member right now.' });
  }
});

app.get('/api/members/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const result = await pool.query('UPDATE members SET is_verified = true, verified_at = now(), verification_token = NULL WHERE verification_token = $1 RETURNING id, email', [token]);

    if (!result.rowCount) {
      return res.status(400).send('<html><body><h2>Verification failed</h2><p>This link is invalid or already used.</p></body></html>');
    }

    return res.send(`
      <html>
        <head><meta charset="UTF-8" /><title>Email Verified</title></head>
        <body style="font-family: Arial, sans-serif; background:#0d1324; color:#eef4ff; display:grid; place-items:center; min-height:100vh; margin:0;">
          <div style="background:#101827; border:1px solid rgba(255,255,255,.1); padding:2rem 3rem; border-radius:16px; text-align:center;">
            <h2 style="margin-top:0;">✅ Email verified</h2>
            <p>Your SAHRUDAYA member account is now active.</p>
            <p><a href="/member-login.html" style="color:#7dd3fc;">Go to member login</a></p>
          </div>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('Member verification error:', error);
    return res.status(500).send('Verification failed. Please try again later.');
  }
});

app.post('/api/members/resend-verification', async (req, res) => {
  try {
    const cleanEmail = String(req.body.email || '').trim().toLowerCase();
    if (!cleanEmail) {
      return res.status(400).json({ status: 'error', message: 'Email is required.' });
    }

    const memberResult = await pool.query('SELECT id, name, is_verified FROM members WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
    if (!memberResult.rowCount) {
      return res.json({ status: 'ok', message: 'If an account exists for this email, a verification link has been sent.' });
    }

    const member = memberResult.rows[0];
    if (member.is_verified) {
      return res.json({ status: 'ok', message: 'This email is already verified. You can log in.' });
    }

    const verificationToken = crypto.randomBytes(20).toString('hex');
    await pool.query('UPDATE members SET verification_token = $1 WHERE id = $2', [verificationToken, member.id]);

    const verificationUrl = `${getBaseUrl(req)}/api/members/verify/${verificationToken}`;
    const emailSent = await sendMemberEmail(
      cleanEmail,
      'Verify your SAHRUDAYA member account',
      `<p>Hello ${escapeHtml(member.name)},</p><p>Click the link below to verify your SAHRUDAYA member account:</p><p><a href="${verificationUrl}">Verify my email</a></p>`,
      'Member verification email',
      verificationUrl
    );

    return res.json({
      status: 'ok',
      message: emailSent
        ? 'A new verification link has been sent. Check your inbox and spam folder.'
        : 'Email delivery could not be completed with server mail settings. Use the direct link below to verify:',
      verificationUrl: emailSent ? undefined : verificationUrl
    });
  } catch (error) {
    console.error('Resend verification error:', error);
    return res.status(500).json({ status: 'error', message: 'Unable to resend the verification email.' });
  }
});

app.post('/api/members/login', async (req, res) => {
  try {
    const identifier = String(req.body.identifier || req.body.email || req.body.username || '').trim();
    const password = String(req.body.password || '');
    if (!identifier || !password) {
      return res.status(400).json({ status: 'error', message: 'Email/username and password are required.' });
    }

    const ipAddress = req.ip;
    if (isLoginRateLimited(ipAddress)) {
      return res.status(429).json({ status: 'error', message: 'Too many login attempts. Try again later.' });
    }

    const adminAuth = await authenticateAdminCredentials(identifier, password);
    if (adminAuth.status === 'ok') {
      loginAttempts.delete(ipAddress);
      clearAuthCookie(res, MEMBER_SESSION_COOKIE);
      setAuthCookie(res, SESSION_COOKIE, createSessionToken(adminAuth.admin));
      return res.json({
        status: 'ok',
        role: 'admin',
        redirectTo: '/admin.html',
        admin: {
          id: adminAuth.admin.id,
          username: adminAuth.admin.username,
          email: adminAuth.admin.email,
          name: adminAuth.admin.name,
        },
      });
    }

    if (adminAuth.status === 'disabled') {
      return res.status(403).json({ status: 'error', message: 'This administrator account is disabled.' });
    }

    const cleanEmail = identifier.toLowerCase();
    const memberResult = await pool.query('SELECT * FROM members WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
    if (!memberResult.rowCount) {
      recordFailedLogin(ipAddress);
      return res.status(401).json({ status: 'error', message: 'Invalid credentials.' });
    }

    const member = memberResult.rows[0];
    if (member.is_active === false) {
      return res.status(403).json({ status: 'error', message: 'Your account has been disabled by an administrator.' });
    }

    const passwordMatches = await bcrypt.compare(password, member.password_hash || '');
    if (!passwordMatches) {
      recordFailedLogin(ipAddress);
      return res.status(401).json({ status: 'error', message: 'Invalid email or password.' });
    }

    if (!member.is_verified) {
      const verificationToken = member.verification_token || crypto.randomBytes(20).toString('hex');
      if (!member.verification_token) {
        await pool.query('UPDATE members SET verification_token = $1 WHERE id = $2', [verificationToken, member.id]);
      }
      const verificationUrl = `${getBaseUrl(req)}/api/members/verify/${verificationToken}`;
      return res.status(401).json({
        status: 'error',
        unverified: true,
        verificationUrl,
        message: 'Please verify your email before logging in.'
      });
    }

    loginAttempts.delete(ipAddress);
    clearAuthCookie(res, SESSION_COOKIE);
    setAuthCookie(res, MEMBER_SESSION_COOKIE, createMemberSessionToken(member.email));
    return res.json({
      status: 'ok',
      role: 'member',
      redirectTo: '/',
      member: { name: member.name, email: member.email, city: member.city, interest: member.interest },
    });
  } catch (error) {
    console.error('Member login error:', error);
    return res.status(500).json({ status: 'error', message: 'Unable to log in right now.' });
  }
});

app.post('/api/members/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const cleanEmail = String(email || '').trim().toLowerCase();

    if (!cleanEmail) {
      return res.status(400).json({ status: 'error', message: 'Email is required.' });
    }

    const existing = await pool.query('SELECT id FROM members WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
    if (!existing.rowCount) {
      return res.json({
        status: 'ok',
        message: 'If an account exists for this email, a password reset link has been sent.'
      });
    }

    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    await pool.query(
      'UPDATE members SET reset_token = $1, reset_expires_at = $2 WHERE LOWER(email) = LOWER($3)',
      [token, expiresAt, cleanEmail]
    );

    const resetUrl = `${getBaseUrl(req)}/reset-password.html?token=${token}`;
    const emailSent = await sendMemberEmail(
      cleanEmail,
      'Reset your SAHRUDAYA password',
      `<p>We received a request to reset your SAHRUDAYA password.</p><p>This link expires in one hour:</p><p><a href="${resetUrl}">Reset my password</a></p>`,
      'Password reset email',
      resetUrl
    );

    return res.json({
      status: 'ok',
      message: emailSent
        ? 'If an account exists for this email, a password reset link has been sent.'
        : 'Email delivery could not be completed with server mail settings. Use the direct link below to reset your password:',
      resetUrl: emailSent ? undefined : resetUrl
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    const message = error.code === 'EAUTH'
      ? 'Password reset email could not be sent. Check the SMTP username and Gmail App Password in .env.'
      : 'Unable to process the password reset request.';
    return res.status(500).json({ status: 'error', message });
  }
});

app.post('/api/members/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    const cleanPassword = String(password || '').trim();

    if (!token || cleanPassword.length < 6) {
      return res.status(400).json({
        status: 'error',
        message: 'A valid reset token and a new password of at least 6 characters are required.'
      });
    }

    const memberResult = await pool.query(
      'SELECT id, email FROM members WHERE reset_token = $1 AND reset_expires_at > NOW()',
      [token]
    );

    if (!memberResult.rowCount) {
      return res.status(400).json({ status: 'error', message: 'This reset link is invalid or has expired.' });
    }

    const member = memberResult.rows[0];
    const newPasswordHash = await bcrypt.hash(cleanPassword, 10);

    await pool.query(
      'UPDATE members SET password_hash = $1, reset_token = NULL, reset_expires_at = NULL, is_verified = true, verified_at = COALESCE(verified_at, NOW()) WHERE id = $2',
      [newPasswordHash, member.id]
    );

    return res.json({ status: 'ok', message: 'Your password has been reset successfully.' });
  } catch (error) {
    console.error('Password reset error:', error);
    return res.status(500).json({ status: 'error', message: 'Unable to reset your password right now.' });
  }
});

app.post('/api/members/logout', (req, res) => {
  clearAuthCookie(res, MEMBER_SESSION_COOKIE);
  return res.json({ status: 'ok' });
});

app.get('/api/members/me', requireMember, async (req, res) => {
  try {
    const session = parseSignedCookie(req, MEMBER_SESSION_COOKIE);
    if (!session || !session.email) {
      return res.status(401).json({ status: 'error', message: 'Member login required' });
    }

    const member = await pool.query(
      'SELECT name, email, phone, city, interest, created_at, is_verified, is_active FROM members WHERE LOWER(email) = LOWER($1)',
      [session.email]
    );

    if (!member.rowCount) {
      return res.status(404).json({ status: 'error', message: 'Member not found' });
    }
    if (member.rows[0].is_active === false) {
      clearAuthCookie(res, MEMBER_SESSION_COOKIE);
      return res.status(403).json({ status: 'error', message: 'Your account has been disabled by an administrator.' });
    }

    return res.json(member.rows[0]);
  } catch (error) {
    console.error('Fetch member details error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
  return res.json({
    id: req.admin.id,
    username: req.admin.username,
    email: req.admin.email,
    name: req.admin.name,
  });
});

app.put('/api/admin/password', requireAdmin, async (req, res) => {
  try {
    if (!req.admin.id) {
      return res.status(400).json({ status: 'error', message: 'Environment-based fallback admins must update password in .env.' });
    }
    const currentPassword = String(req.body.currentPassword || '');
    const newPassword = String(req.body.newPassword || '').trim();
    if (newPassword.length < 6) {
      return res.status(400).json({ status: 'error', message: 'New password must be at least 6 characters.' });
    }

    const { rows } = await pool.query('SELECT password_hash FROM admins WHERE id = $1', [req.admin.id]);
    if (!rows.length || !(await bcrypt.compare(currentPassword, rows[0].password_hash))) {
      return res.status(401).json({ status: 'error', message: 'Current password is incorrect.' });
    }

    const nextHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE admins SET password_hash = $1 WHERE id = $2', [nextHash, req.admin.id]);
    return res.json({ status: 'ok', message: 'Admin password updated.' });
  } catch (error) {
    console.error('Update admin password error:', error);
    return res.status(500).json({ status: 'error', message: 'Unable to update password.' });
  }
});

app.get('/api/admins', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, email, name, is_active, created_at FROM admins ORDER BY created_at ASC'
    );
    const enriched = rows.map((admin) => ({
      ...admin,
      is_permanent: admin.username.toLowerCase() === PERMANENT_ADMIN_IDENTIFIER.toLowerCase()
        || admin.email.toLowerCase() === PERMANENT_ADMIN_IDENTIFIER.toLowerCase(),
    }));
    return res.json(enriched);
  } catch (error) {
    console.error('Fetch admins error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
});

app.post('/api/admins', requireAdmin, async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const name = String(req.body.name || username).trim();
    const password = String(req.body.password || '').trim();

    if (!username || !email || !name || password.length < 6) {
      return res.status(400).json({ status: 'error', message: 'Username, email, name, and password (min 6 chars) are required.' });
    }

    const duplicate = await pool.query(
      'SELECT id FROM admins WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2)',
      [username, email]
    );
    if (duplicate.rowCount) {
      return res.status(409).json({ status: 'error', message: 'An admin with that username or email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO admins(username, email, name, password_hash, is_active) VALUES($1, $2, $3, $4, true) RETURNING id, username, email, name, is_active, created_at',
      [username, email, name, passwordHash]
    );
    return res.status(201).json({ status: 'ok', admin: rows[0] });
  } catch (error) {
    console.error('Create admin error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not create admin user.' });
  }
});

app.patch('/api/admins/:id', requireAdmin, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    if (!Number.isInteger(targetId)) {
      return res.status(400).json({ status: 'error', message: 'Invalid admin ID.' });
    }

    const existing = await pool.query('SELECT id, username, email, is_active FROM admins WHERE id = $1', [targetId]);
    if (!existing.rowCount) {
      return res.status(404).json({ status: 'error', message: 'Admin user not found.' });
    }

    const isPermanent = existing.rows[0].username.toLowerCase() === PERMANENT_ADMIN_IDENTIFIER.toLowerCase()
      || existing.rows[0].email.toLowerCase() === PERMANENT_ADMIN_IDENTIFIER.toLowerCase();

    if (typeof req.body.is_active === 'boolean') {
      if (isPermanent && req.body.is_active === false) {
        return res.status(403).json({ status: 'error', message: `The primary admin (${PERMANENT_ADMIN_IDENTIFIER}) is permanent and cannot be disabled.` });
      }
      if (targetId === req.admin.id && req.body.is_active === false) {
        return res.status(400).json({ status: 'error', message: 'You cannot disable your own active admin session.' });
      }
      await pool.query('UPDATE admins SET is_active = $1 WHERE id = $2', [req.body.is_active, targetId]);
    }

    if (req.body.password) {
      const cleanPass = String(req.body.password).trim();
      if (cleanPass.length < 6) {
        return res.status(400).json({ status: 'error', message: 'Password must be at least 6 characters.' });
      }
      const hash = await bcrypt.hash(cleanPass, 10);
      await pool.query('UPDATE admins SET password_hash = $1 WHERE id = $2', [hash, targetId]);
    }

    const { rows } = await pool.query(
      'SELECT id, username, email, name, is_active, created_at FROM admins WHERE id = $1',
      [targetId]
    );
    return res.json({ status: 'ok', admin: rows[0] });
  } catch (error) {
    console.error('Update admin error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not update admin user.' });
  }
});

app.delete('/api/admins/:id', requireAdmin, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    if (targetId === req.admin.id) {
      return res.status(400).json({ status: 'error', message: 'You cannot delete the currently signed-in admin.' });
    }

    const existing = await pool.query('SELECT id, username, email FROM admins WHERE id = $1', [targetId]);
    if (!existing.rowCount) {
      return res.status(404).json({ status: 'error', message: 'Admin user not found.' });
    }

    const isPermanent = existing.rows[0].username.toLowerCase() === PERMANENT_ADMIN_IDENTIFIER.toLowerCase()
      || existing.rows[0].email.toLowerCase() === PERMANENT_ADMIN_IDENTIFIER.toLowerCase();

    if (isPermanent) {
      return res.status(403).json({ status: 'error', message: `The primary system admin (${PERMANENT_ADMIN_IDENTIFIER}) is permanent and cannot be deleted or removed.` });
    }

    const countResult = await pool.query('SELECT COUNT(*)::int AS count FROM admins WHERE is_active = true');
    if (countResult.rows[0].count <= 1) {
      return res.status(400).json({ status: 'error', message: 'At least one active admin must remain.' });
    }

    await pool.query('DELETE FROM admins WHERE id = $1', [targetId]);
    return res.json({ status: 'ok' });
  } catch (error) {
    console.error('Delete admin error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not delete admin user.' });
  }
});

app.get('/api/members', requireAdmin, async (req, res) => {
  try {
    const q = 'SELECT id, name, email, phone, city, interest, is_verified, is_active, created_at FROM members ORDER BY created_at DESC';
    const { rows } = await pool.query(q);
    return res.json(rows);
  } catch (error) {
    console.error('Fetch members error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
});

app.post('/api/members', requireAdmin, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const phone = String(req.body.phone || '').trim();
    const city = String(req.body.city || '').trim();
    const interest = String(req.body.interest || '').trim();
    const password = String(req.body.password || '').trim();
    const isVerified = req.body.is_verified !== false;
    const isActive = req.body.is_active !== false;

    if (!name || !email || !phone || !city || !interest || password.length < 6) {
      return res.status(400).json({ status: 'error', message: 'All member fields and a password of at least 6 characters are required.' });
    }

    const existing = await pool.query('SELECT id FROM members WHERE LOWER(email) = LOWER($1)', [email]);
    if (existing.rowCount) {
      return res.status(409).json({ status: 'error', message: 'A member with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO members(name, email, phone, city, interest, password_hash, is_verified, is_active, verified_at)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id, name, email, phone, city, interest, is_verified, is_active, created_at`,
      [name, email, phone, city, interest, passwordHash, isVerified, isActive, isVerified ? new Date().toISOString() : null]
    );
    return res.status(201).json({ status: 'ok', member: rows[0] });
  } catch (error) {
    console.error('Admin create member error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not create member.' });
  }
});

app.put('/api/members/:id', requireAdmin, async (req, res) => {
  try {
    const memberId = Number(req.params.id);
    if (!Number.isInteger(memberId)) {
      return res.status(400).json({ status: 'error', message: 'Invalid member ID.' });
    }

    const existing = await pool.query('SELECT * FROM members WHERE id = $1', [memberId]);
    if (!existing.rowCount) {
      return res.status(404).json({ status: 'error', message: 'Member not found.' });
    }

    const current = existing.rows[0];
    const name = req.body.name !== undefined ? String(req.body.name).trim() : current.name;
    const email = req.body.email !== undefined ? String(req.body.email).trim().toLowerCase() : current.email;
    const phone = req.body.phone !== undefined ? String(req.body.phone).trim() : current.phone;
    const city = req.body.city !== undefined ? String(req.body.city).trim() : current.city;
    const interest = req.body.interest !== undefined ? String(req.body.interest).trim() : current.interest;
    const isVerified = typeof req.body.is_verified === 'boolean' ? req.body.is_verified : current.is_verified;
    const isActive = typeof req.body.is_active === 'boolean' ? req.body.is_active : current.is_active;

    if (!name || !email || !phone || !city || !interest) {
      return res.status(400).json({ status: 'error', message: 'Name, email, phone, city, and interest cannot be empty.' });
    }

    const duplicate = await pool.query('SELECT id FROM members WHERE LOWER(email) = LOWER($1) AND id <> $2', [email, memberId]);
    if (duplicate.rowCount) {
      return res.status(409).json({ status: 'error', message: 'Another member already uses that email.' });
    }

    let passwordHash = current.password_hash;
    if (req.body.password) {
      const cleanPassword = String(req.body.password).trim();
      if (cleanPassword.length < 6) {
        return res.status(400).json({ status: 'error', message: 'Password must be at least 6 characters.' });
      }
      passwordHash = await bcrypt.hash(cleanPassword, 10);
    }

    const { rows } = await pool.query(
      `UPDATE members
       SET name = $1, email = $2, phone = $3, city = $4, interest = $5,
           is_verified = $6, is_active = $7, password_hash = $8,
           verified_at = CASE WHEN $6 AND verified_at IS NULL THEN NOW() ELSE verified_at END
       WHERE id = $9
       RETURNING id, name, email, phone, city, interest, is_verified, is_active, created_at`,
      [name, email, phone, city, interest, isVerified, isActive, passwordHash, memberId]
    );
    return res.json({ status: 'ok', member: rows[0] });
  } catch (error) {
    console.error('Update member error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not update member.' });
  }
});

app.delete('/api/members/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM members WHERE id = $1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ status: 'error', message: 'Member not found' });
    return res.json({ status: 'ok' });
  } catch (error) {
    console.error('Delete member error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not delete member' });
  }
});

app.get('/api/events', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, title, description, event_date, location FROM events WHERE event_date >= NOW() ORDER BY event_date ASC');
    return res.json(rows);
  } catch (error) {
    console.error('Fetch events error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
});

app.get('/api/admin/events', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, title, description, event_date, location, created_at FROM events ORDER BY event_date DESC');
    return res.json(rows);
  } catch (error) {
    console.error('Fetch admin events error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
});

app.post('/api/events', requireAdmin, async (req, res) => {
  try {
    const title = String(req.body.title || '').trim();
    const description = String(req.body.description || '').trim();
    const location = String(req.body.location || '').trim();
    const eventDate = String(req.body.eventDate || '').trim();

    if (!title || !description || !location || !eventDate || Number.isNaN(Date.parse(eventDate))) {
      return res.status(400).json({ status: 'error', message: 'Enter a title, description, date, and location.' });
    }

    const eventResult = await pool.query(
      'INSERT INTO events(title, description, event_date, location) VALUES($1, $2, $3, $4) RETURNING id, title, description, event_date, location',
      [title, description, eventDate, location]
    );
    const event = eventResult.rows[0];
    const memberResult = await pool.query('SELECT name, email FROM members WHERE is_verified = true AND is_active = true');
    const eventDateText = new Date(event.event_date).toLocaleString();
    const notifications = memberResult.rows.map((member) => sendMemberEmail(
      member.email,
      `New SAHRUDAYA event: ${event.title}`,
      `<p>Hello ${escapeHtml(member.name)},</p><p>A new SAHRUDAYA event has been announced:</p><h2>${escapeHtml(event.title)}</h2><p>${escapeHtml(event.description)}</p><p><strong>Date:</strong> ${escapeHtml(eventDateText)}<br><strong>Location:</strong> ${escapeHtml(event.location)}</p>`,
      'Event notification email',
      event.title
    ));
    const notificationResults = await Promise.allSettled(notifications);
    const sentCount = notificationResults.filter((result) => result.status === 'fulfilled' && result.value).length;

    return res.status(201).json({ status: 'ok', event, notifiedMembers: sentCount });
  } catch (error) {
    console.error('Create event error:', error);
    return res.status(500).json({ status: 'error', message: 'Unable to publish event.' });
  }
});

app.put('/api/events/:id', requireAdmin, async (req, res) => {
  try {
    const title = String(req.body.title || '').trim();
    const description = String(req.body.description || '').trim();
    const location = String(req.body.location || '').trim();
    const eventDate = String(req.body.eventDate || '').trim();

    if (!title || !description || !location || !eventDate || Number.isNaN(Date.parse(eventDate))) {
      return res.status(400).json({ status: 'error', message: 'Enter a valid title, description, date, and location.' });
    }

    const { rows } = await pool.query(
      'UPDATE events SET title = $1, description = $2, event_date = $3, location = $4 WHERE id = $5 RETURNING id, title, description, event_date, location',
      [title, description, eventDate, location, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ status: 'error', message: 'Event not found.' });
    return res.json({ status: 'ok', event: rows[0] });
  } catch (error) {
    console.error('Update event error:', error);
    return res.status(500).json({ status: 'error', message: 'Unable to update event.' });
  }
});

app.delete('/api/events/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM events WHERE id = $1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ status: 'error', message: 'Event not found.' });
    return res.json({ status: 'ok' });
  } catch (error) {
    console.error('Delete event error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not delete event.' });
  }
});

app.get('/api/settings', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT key, value FROM app_settings');
    const settings = { ...DEFAULT_APP_SETTINGS };
    rows.forEach((row) => {
      settings[row.key] = row.value;
    });
    return res.json(settings);
  } catch (error) {
    console.error('Fetch settings error:', error);
    return res.json(DEFAULT_APP_SETTINGS);
  }
});

app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    const allowedKeys = Object.keys(DEFAULT_APP_SETTINGS);
    for (const key of allowedKeys) {
      if (req.body[key] !== undefined) {
        const cleanVal = String(req.body[key]).trim();
        await pool.query(
          'INSERT INTO app_settings(key, value, updated_at) VALUES($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()',
          [key, cleanVal]
        );
      }
    }

    const { rows } = await pool.query('SELECT key, value FROM app_settings');
    const settings = { ...DEFAULT_APP_SETTINGS };
    rows.forEach((row) => {
      settings[row.key] = row.value;
    });
    return res.json({ status: 'ok', settings });
  } catch (error) {
    console.error('Update settings error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not save application settings.' });
  }
});

// Prevent exposure of sensitive source, environment, or lock files via static serving
app.use((req, res, next) => {
  const blockedFiles = ['/server.js', '/package.json', '/package-lock.json', '/env.example', '/.env', '/readme.md'];
  const reqPath = (req.path || '').toLowerCase();
  if (blockedFiles.includes(reqPath) || reqPath.startsWith('/.env')) {
    return res.status(404).sendFile(path.join(__dirname, 'index.html'));
  }
  next();
});

app.use(express.static(path.join(__dirname), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    }
  }
}));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  if (process.env.NODE_ENV === 'production' && SESSION_SECRET === 'sahrudaya-dev-secret-change-me') {
    console.warn('⚠️ WARNING: Using default SESSION_SECRET in production. Set SESSION_SECRET in your environment variables.');
  }
  console.log(`Server started on http://localhost:${PORT}`);
});
