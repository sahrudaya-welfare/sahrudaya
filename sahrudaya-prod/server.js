const express = require('express');
require('dotenv').config();
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const multer = require('multer');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || process.env.NEON_DATABASE_URL || 'postgresql://postgres:postgres@127.0.0.1:5432/sahrudaya';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const SESSION_SECRET = process.env.SESSION_SECRET || 'sahrudaya-dev-secret-change-me';
const SESSION_COOKIE = 'admin_session';
const MEMBER_SESSION_COOKIE = 'member_session';
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
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, callback) => {
    callback(null, ['image/jpeg', 'image/png', 'image/webp', 'image/gif'].includes(file.mimetype));
  },
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

async function sendMemberEmail(to, subject, html, fallbackLabel, fallbackUrl) {
  if (!mailTransporter) {
    console.log(`${fallbackLabel}: ${fallbackUrl}`);
    return false;
  }

  await mailTransporter.sendMail({
    from: SMTP_FROM || `SAHRUDAYA <${SMTP_USER || GMAIL_USER}>`,
    to,
    subject,
    html,
  });
  return true;
}

function createSessionToken(username) {
  const payload = Buffer.from(JSON.stringify({ username, expiresAt: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
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

function createMemberSessionToken(email) {
  const payload = Buffer.from(JSON.stringify({ email, expiresAt: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function isAuthenticated(req) {
  if (!SESSION_SECRET) return false;

  const cookies = req.headers.cookie || '';
  const sessionCookie = cookies.split(';').map((cookie) => cookie.trim()).find((cookie) => cookie.startsWith(`${SESSION_COOKIE}=`));
  if (!sessionCookie) return false;

  const token = sessionCookie.slice(`${SESSION_COOKIE}=`.length);
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;

  const expectedSignature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const signaturesMatch = signature.length === expectedSignature.length
    && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
  if (!signaturesMatch) return false;

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return session.username === ADMIN_USERNAME && session.expiresAt > Date.now();
  } catch (error) {
    return false;
  }
}

function requireAdmin(req, res, next) {
  if (isAuthenticated(req)) return next();
  return res.status(401).json({ status: 'error', message: 'Admin login required' });
}

function isMemberAuthenticated(req) {
  if (!SESSION_SECRET) return false;

  const cookies = req.headers.cookie || '';
  const memberCookie = cookies.split(';').map((cookie) => cookie.trim()).find((cookie) => cookie.startsWith(`${MEMBER_SESSION_COOKIE}=`));
  if (!memberCookie) return false;

  const token = memberCookie.slice(`${MEMBER_SESSION_COOKIE}=`.length);
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;

  const expectedSignature = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const signaturesMatch = signature.length === expectedSignature.length
    && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
  if (!signaturesMatch) return false;

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return !!session.email && session.expiresAt > Date.now();
  } catch (error) {
    return false;
  }
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

app.get('/admin', (req, res) => {
  res.redirect(isAuthenticated(req) ? '/admin.html' : '/admin-login.html');
});

app.get('/admin.html', (req, res) => {
  if (!isAuthenticated(req)) return res.redirect('/admin-login.html');
  return res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/member-login', (req, res) => {
  res.redirect('/member-login.html');
});

app.get('/member-register', (req, res) => {
  res.redirect('/member-register.html');
});

app.get('/member-dashboard', (req, res) => {
  if (!isMemberAuthenticated(req)) return res.redirect('/member-login.html');
  return res.sendFile(path.join(__dirname, 'member-dashboard.html'));
});

app.post('/api/admin/login', async (req, res) => {
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH || !SESSION_SECRET) {
    return res.status(500).json({ status: 'error', message: 'Admin login is not configured on the server' });
  }

  const ipAddress = req.ip;
  if (isLoginRateLimited(ipAddress)) {
    return res.status(429).json({ status: 'error', message: 'Too many login attempts. Try again later.' });
  }

  const { username, password } = req.body;
  const usernameMatches = username === ADMIN_USERNAME;
  const passwordMatches = await bcrypt.compare(password || '', ADMIN_PASSWORD_HASH);
  if (!usernameMatches || !passwordMatches) {
    recordFailedLogin(ipAddress);
    return res.status(401).json({ status: 'error', message: 'Invalid username or password' });
  }

  loginAttempts.delete(ipAddress);

  const secureFlag = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${createSessionToken(username)}; HttpOnly; SameSite=Lax; Path=/${secureFlag}`);
  return res.json({ status: 'ok' });
});

app.post('/api/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/`);
  return res.json({ status: 'ok' });
});

function clearAdminSession(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/`);
}

app.get(['/', '/index.html'], (req, res) => {
  clearAdminSession(res);
  return res.sendFile(path.join(__dirname, 'index.html'));
});

// PostgreSQL (Neon) pool
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('neon') ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 10000,
  query_timeout: 15000,
});

pool.on('error', (error) => {
  console.error('Postgres pool connection error:', error);
});

async function initDB() {
  // create tables if they don't exist
  const createTableQuery = `
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
    ALTER TABLE members ADD COLUMN IF NOT EXISTS verification_token TEXT;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS reset_token TEXT;
    ALTER TABLE members ADD COLUMN IF NOT EXISTS reset_expires_at TIMESTAMPTZ;
  `;
  await pool.query(migrationQuery);
  console.log('Postgres initialized / tables ready');
}

initDB().catch((err) => console.error('Init DB error:', err));

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

app.post('/api/members/register', async (req, res) => {
  try {
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

    const existing = await pool.query('SELECT id FROM members WHERE email = $1', [cleanEmail]);
    if (existing.rowCount) {
      return res.status(409).json({ status: 'error', message: 'A member with this email already exists.' });
    }

    const verificationToken = crypto.randomBytes(20).toString('hex');
    const passwordHash = await bcrypt.hash(cleanPassword, 10);

    const insertQuery = `
      INSERT INTO members(name, email, phone, city, interest, password_hash, verification_token, is_verified)
      VALUES($1, $2, $3, $4, $5, $6, $7, false)
      RETURNING id, created_at
    `;

    const result = await pool.query(insertQuery, [cleanName, cleanEmail, cleanPhone, cleanCity, cleanInterest, passwordHash, verificationToken]);

    const verificationUrl = `${process.env.APP_BASE_URL || 'http://localhost:3000'}/api/members/verify/${verificationToken}`;
    let emailSent = false;
    try {
      emailSent = await sendMemberEmail(
        cleanEmail,
        'SAHRUDAYA registration successful - verify your email',
        `<p>Hello ${cleanName},</p><p>Your SAHRUDAYA member registration was successfully received.</p><p>Click the link below to verify your email and activate your account:</p><p><a href="${verificationUrl}">Verify my email</a></p>`,
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

    const memberResult = await pool.query('SELECT id, name, is_verified FROM members WHERE email = $1', [cleanEmail]);
    if (!memberResult.rowCount) {
      return res.json({ status: 'ok', message: 'If an account exists for this email, a verification link has been sent.' });
    }

    const member = memberResult.rows[0];
    if (member.is_verified) {
      return res.json({ status: 'ok', message: 'This email is already verified. You can log in.' });
    }

    const verificationToken = crypto.randomBytes(20).toString('hex');
    await pool.query('UPDATE members SET verification_token = $1 WHERE id = $2', [verificationToken, member.id]);

    const verificationUrl = `${process.env.APP_BASE_URL || 'http://localhost:3000'}/api/members/verify/${verificationToken}`;
    const emailSent = await sendMemberEmail(
      cleanEmail,
      'Verify your SAHRUDAYA member account',
      `<p>Hello ${member.name},</p><p>Click the link below to verify your SAHRUDAYA member account:</p><p><a href="${verificationUrl}">Verify my email</a></p>`,
      'Member verification email',
      verificationUrl
    );

    return res.json({
      status: 'ok',
      message: emailSent
        ? 'A new verification link has been sent. Check your inbox and spam folder.'
        : 'Email is not configured; use the verification link printed in the server terminal.',
      verificationUrl: emailSent ? undefined : verificationUrl
    });
  } catch (error) {
    console.error('Resend verification error:', error);
    return res.status(500).json({ status: 'error', message: 'Unable to resend the verification email.' });
  }
});

app.post('/api/members/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ status: 'error', message: 'Email and password are required.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const memberResult = await pool.query('SELECT * FROM members WHERE email = $1', [cleanEmail]);
    if (!memberResult.rowCount) {
      return res.status(401).json({ status: 'error', message: 'Invalid email or password.' });
    }

    const member = memberResult.rows[0];
    const passwordMatches = await bcrypt.compare(String(password), member.password_hash || '');
    if (!passwordMatches || !member.is_verified) {
      return res.status(401).json({
        status: 'error',
        message: member.is_verified ? 'Invalid email or password.' : 'Please verify your email before logging in.'
      });
    }

    const secureFlag = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `${MEMBER_SESSION_COOKIE}=${createMemberSessionToken(member.email)}; HttpOnly; SameSite=Lax; Max-Age=28800; Path=/${secureFlag}`);
    return res.json({ status: 'ok', member: { name: member.name, email: member.email, city: member.city, interest: member.interest } });
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

    const existing = await pool.query('SELECT id FROM members WHERE email = $1', [cleanEmail]);
    if (!existing.rowCount) {
      return res.json({
        status: 'ok',
        message: 'If an account exists for this email, a password reset link has been sent.'
      });
    }

    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    await pool.query(
      'UPDATE members SET reset_token = $1, reset_expires_at = $2 WHERE email = $3',
      [token, expiresAt, cleanEmail]
    );

    const resetUrl = `${process.env.APP_BASE_URL || 'http://localhost:3000'}/reset-password.html?token=${token}`;
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
        : 'Email is not configured; use the reset link printed in the server terminal.',
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
  res.setHeader('Set-Cookie', `${MEMBER_SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/`);
  return res.json({ status: 'ok' });
});

app.get('/api/members/me', requireMember, async (req, res) => {
  try {
    const cookies = req.headers.cookie || '';
    const memberCookie = cookies.split(';').map((cookie) => cookie.trim()).find((cookie) => cookie.startsWith(`${MEMBER_SESSION_COOKIE}=`));
    if (!memberCookie) {
      return res.status(401).json({ status: 'error', message: 'Member login required' });
    }

    const token = memberCookie.slice(`${MEMBER_SESSION_COOKIE}=`.length);
    const [, signature] = token.split('.');
    if (!signature) {
      return res.status(401).json({ status: 'error', message: 'Session expired' });
    }

    const payload = token.split('.')[0];
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    const member = await pool.query('SELECT name, email, phone, city, interest, created_at, is_verified FROM members WHERE email = $1', [session.email]);

    if (!member.rowCount) {
      return res.status(404).json({ status: 'error', message: 'Member not found' });
    }

    return res.json(member.rows[0]);
  } catch (error) {
    console.error('Fetch member details error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
});

app.get('/api/members', requireAdmin, async (req, res) => {
  try {
    const q = 'SELECT id, name, email, phone, city, interest, created_at FROM members ORDER BY created_at DESC';
    const { rows } = await pool.query(q);
    return res.json(rows);
  } catch (error) {
    console.error('Fetch members error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
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
    const memberResult = await pool.query('SELECT name, email FROM members WHERE is_verified = true');
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

app.get('/api/images', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, filename FROM gallery_images ORDER BY created_at DESC');
    return res.json(rows.map((image) => ({ ...image, url: `/api/images/${image.id}` })));
  } catch (error) {
    console.error('Fetch gallery images error:', error);
    return res.status(500).json({ status: 'error', message: 'Server error' });
  }
});

app.get('/api/images/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT mime_type, image_data FROM gallery_images WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).send('Image not found');
    res.setHeader('Content-Type', rows[0].mime_type);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    return res.send(rows[0].image_data);
  } catch (error) {
    console.error('Fetch gallery image error:', error);
    return res.status(500).send('Server error');
  }
});

app.post('/api/images', requireAdmin, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ status: 'error', message: 'Choose a valid image under 5 MB' });
  }

  try {
    const query = 'INSERT INTO gallery_images(filename, mime_type, image_data) VALUES($1, $2, $3) RETURNING id';
    const { rows } = await pool.query(query, [req.file.originalname, req.file.mimetype, req.file.buffer]);
    return res.status(201).json({ status: 'ok', id: rows[0].id });
  } catch (error) {
    console.error('Upload gallery image error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not save image' });
  }
});

app.delete('/api/images/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM gallery_images WHERE id = $1', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ status: 'error', message: 'Image not found' });
    return res.json({ status: 'ok' });
  } catch (error) {
    console.error('Delete gallery image error:', error);
    return res.status(500).json({ status: 'error', message: 'Could not delete image' });
  }
});

app.use(express.static(path.join(__dirname)));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
});
