require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'rebel_ink';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('JWT_SECRET must be set and at least 32 characters long.');
  process.exit(1);
}
if (!MONGODB_URI) {
  console.error('MONGODB_URI must be set. Use a persistent MongoDB Atlas database.');
  process.exit(1);
}
if (!ADMIN_EMAIL || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error('ADMIN_EMAIL and ADMIN_PASSWORD must be set; ADMIN_PASSWORD must be at least 12 characters.');
  process.exit(1);
}

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: false, limit: '20mb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many authentication attempts. Please try again later.' } });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });

let client;
let db;
let users;
let bookings;

function safeUser(u) {
  if (!u) return null;
  return {
    _id: String(u._id),
    name: u.name,
    phone: u.phone,
    country: u.country,
    state: u.state || '',
    email: u.email,
    role: u.role,
    status: u.status,
    adminNotes: u.adminNotes || '',
    createdAt: u.createdAt,
    updatedAt: u.updatedAt,
    lastLoginAt: u.lastLoginAt || null
  };
}

function tokenFor(user) {
  return jwt.sign({ sub: String(user._id), role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '7d', issuer: 'rebel-ink' });
}

function isObjectId(id) { return ObjectId.isValid(id); }

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Authentication required.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'rebel-ink' });
    if (!isObjectId(payload.sub)) throw new Error('Invalid subject');
    const user = await users.findOne({ _id: new ObjectId(payload.sub) });
    if (!user || user.status === 'suspended') return res.status(401).json({ error: 'Account is unavailable.' });
    req.user = user;
    next();
  } catch (_) {
    return res.status(401).json({ error: 'Invalid or expired session.' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

function cleanText(value, max) {
  return String(value ?? '').trim().slice(0, max);
}

function validPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8 && pw.length <= 128 && /[a-zA-Z]/.test(pw) && /[0-9]/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
}

function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }

function validPhotos(photos) {
  if (!Array.isArray(photos) || photos.length > 5) return false;
  return photos.every(p => p && typeof p.name === 'string' && typeof p.dataUrl === 'string' && /^data:image\/(jpeg|jpg|png|webp|gif);base64,/i.test(p.dataUrl) && p.dataUrl.length <= 3_500_000);
}

function csvEscape(v) {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

async function ensureAdmin() {
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  const existing = await users.findOne({ email: ADMIN_EMAIL });
  if (!existing) {
    await users.insertOne({ name: 'Administrator', phone: '', country: 'United States', state: '', email: ADMIN_EMAIL, passwordHash: hash, role: 'admin', status: 'approved', adminNotes: '', createdAt: new Date(), updatedAt: new Date() });
    console.log(`Admin account created from environment: ${ADMIN_EMAIL}`);
  } else if (existing.role !== 'admin') {
    await users.updateOne({ _id: existing._id }, { $set: { role: 'admin', status: 'approved', passwordHash: hash, updatedAt: new Date() } });
    console.log(`Existing account promoted to admin: ${ADMIN_EMAIL}`);
  } else {
    // Keep the admin password controlled by Render environment variables, never by the HTML.
    await users.updateOne({ _id: existing._id }, { $set: { passwordHash: hash, status: 'approved', updatedAt: new Date() } });
  }
}

async function start() {
  client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  await client.connect();
  db = client.db(DB_NAME);
  users = db.collection('users');
  bookings = db.collection('bookings');

  await users.createIndex({ email: 1 }, { unique: true });
  await users.createIndex({ status: 1, createdAt: -1 });
  await bookings.createIndex({ userId: 1, createdAt: -1 });
  await bookings.createIndex({ status: 1, createdAt: -1 });
  await bookings.createIndex({ date: 1 });
  await ensureAdmin();

  app.get('/api/health', async (_req, res) => res.json({ ok: true, service: 'rebel-ink', time: new Date().toISOString() }));

  app.post('/api/register', authLimiter, async (req, res) => {
    try {
      const name = cleanText(req.body.name, 120);
      const phone = cleanText(req.body.phone, 40);
      const country = cleanText(req.body.country, 80);
      const state = cleanText(req.body.state, 80);
      const email = normalizeEmail(req.body.email);
      const password = req.body.password;
      if (!name || !phone || !country || !email || !validPassword(password)) return res.status(400).json({ error: 'Please provide valid registration details and a strong password.' });
      if (country === 'United States' && !state) return res.status(400).json({ error: 'US state is required.' });
      if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
      const exists = await users.findOne({ email });
      if (exists) return res.status(409).json({ error: 'An account with that email already exists.' });
      const passwordHash = await bcrypt.hash(password, 12);
      const now = new Date();
      const doc = { name, phone, country, state, email, passwordHash, role: 'member', status: 'pending', adminNotes: '', createdAt: now, updatedAt: now };
      await users.insertOne(doc);
      return res.status(201).json({ message: 'Account created. Your account is pending admin approval. You will see the approval status in your member portal.', user: safeUser(doc) });
    } catch (e) {
      if (e && e.code === 11000) return res.status(409).json({ error: 'An account with that email already exists.' });
      console.error(e); res.status(500).json({ error: 'Registration failed.' });
    }
  });

  app.post('/api/login', authLimiter, async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password || '';
    const user = await users.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Invalid email or password.' });
    if (user.status === 'suspended') return res.status(403).json({ error: 'This account is suspended. Contact the administrator.' });
    await users.updateOne({ _id: user._id }, { $set: { lastLoginAt: new Date(), updatedAt: new Date() } });
    res.json({ token: tokenFor(user), user: safeUser(user) });
  });

  app.post('/api/admin/login', authLimiter, async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password || '';
    const user = await users.findOne({ email, role: 'admin' });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Invalid admin credentials.' });
    await users.updateOne({ _id: user._id }, { $set: { lastLoginAt: new Date(), updatedAt: new Date() } });
    res.json({ token: tokenFor(user), user: safeUser(user) });
  });

  app.post('/api/reset-password', authLimiter, async (req, res) => {
    // Kept compatible with the existing UI, but protected by a server-side reset secret.
    // Production password recovery should use a verified email reset flow; this endpoint is disabled unless RESET_PASSWORD_KEY is set.
    const resetKey = process.env.RESET_PASSWORD_KEY;
    if (!resetKey) return res.status(503).json({ error: 'Password reset is not enabled. Contact the administrator.' });
    if (req.headers['x-reset-key'] !== resetKey) return res.status(403).json({ error: 'Password reset authorization required.' });
    const email = normalizeEmail(req.body.email);
    const password = req.body.password || '';
    if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters and include letters, numbers, and a special character.' });
    const user = await users.findOne({ email });
    if (!user) return res.status(404).json({ error: 'Account not found.' });
    const passwordHash = await bcrypt.hash(password, 12);
    await users.updateOne({ _id: user._id }, { $set: { passwordHash, updatedAt: new Date() } });
    res.json({ message: 'Password updated. You can now log in.' });
  });

  app.get('/api/me', auth, async (req, res) => {
    const bs = await bookings.find({ userId: req.user._id }).sort({ createdAt: -1 }).toArray();
    res.json({ user: { ...safeUser(req.user), bookings: bs.map(b => ({ _id: String(b._id), service: b.service, date: b.date || '', problem: b.problem, photos: b.photos || [], status: b.status, adminNote: b.adminNote || '', createdAt: b.createdAt, updatedAt: b.updatedAt })) } });
  });

  app.post('/api/bookings', auth, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.status !== 'approved') return res.status(403).json({ error: 'Your account must be approved before you can book an appointment.' });
    const service = cleanText(req.body.service, 180);
    const date = cleanText(req.body.date, 30);
    const problem = cleanText(req.body.problem, 5000);
    const photos = req.body.photos || [];
    if (!service || !problem) return res.status(400).json({ error: 'Service and problem/goals are required.' });
    if (!validPhotos(photos)) return res.status(400).json({ error: 'Photos must be up to 5 supported images. Please use smaller images if the upload is too large.' });
    if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Invalid preferred date.' });
    const now = new Date();
    const doc = { userId: req.user._id, service, date, problem, photos, status: 'Pending', adminNote: '', createdAt: now, updatedAt: now };
    const result = await bookings.insertOne(doc);
    res.status(201).json({ message: 'Appointment request submitted. Admin review is required.', booking: { ...doc, _id: String(result.insertedId) } });
  });

  app.get('/api/admin/members', auth, adminOnly, adminLimiter, async (_req, res) => {
    const members = await users.find({ role: 'member' }).sort({ createdAt: -1 }).toArray();
    const ids = members.map(m => m._id);
    const bs = await bookings.find({ userId: { $in: ids } }).sort({ createdAt: -1 }).toArray();
    const byUser = new Map();
    for (const b of bs) { const k = String(b.userId); if (!byUser.has(k)) byUser.set(k, []); byUser.get(k).push({ ...b, _id: String(b._id), userId: undefined }); }
    const out = members.map(m => ({ ...safeUser(m), bookings: byUser.get(String(m._id)) || [] }));
    const pendingBookings = bs.filter(b => b.status === 'Pending').length;
    res.json({ members: out, stats: { total: members.length, withBookings: new Set(bs.map(b => String(b.userId))).size, pending: members.filter(m => m.status === 'pending').length, pendingBookings } });
  });

  app.patch('/api/admin/members/:id/status', auth, adminOnly, async (req, res) => {
    if (!isObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid member.' });
    const status = req.body.status;
    if (!['approved', 'suspended', 'pending'].includes(status)) return res.status(400).json({ error: 'Invalid member status.' });
    const r = await users.updateOne({ _id: new ObjectId(req.params.id), role: 'member' }, { $set: { status, updatedAt: new Date() } });
    if (!r.matchedCount) return res.status(404).json({ error: 'Member not found.' });
    res.json({ message: `Member ${status}.` });
  });

  app.patch('/api/admin/members/:id/notes', auth, adminOnly, async (req, res) => {
    if (!isObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid member.' });
    await users.updateOne({ _id: new ObjectId(req.params.id), role: 'member' }, { $set: { adminNotes: cleanText(req.body.notes, 5000), updatedAt: new Date() } });
    res.json({ message: 'Notes saved.' });
  });

  app.patch('/api/admin/bookings/:userId/:bookingId/status', auth, adminOnly, async (req, res) => {
    if (!isObjectId(req.params.userId) || !isObjectId(req.params.bookingId)) return res.status(400).json({ error: 'Invalid booking.' });
    const status = req.body.status;
    if (!['Pending', 'Approved', 'Rejected', 'Done', 'Cancelled'].includes(status)) return res.status(400).json({ error: 'Invalid appointment status.' });
    const now = new Date();
    const update = { status, updatedAt: now, adminNote: cleanText(req.body.adminNote, 3000) };
    if (status === 'Approved') update.approvedAt = now;
    if (status === 'Rejected') update.rejectedAt = now;
    const r = await bookings.updateOne({ _id: new ObjectId(req.params.bookingId), userId: new ObjectId(req.params.userId) }, { $set: update });
    if (!r.matchedCount) return res.status(404).json({ error: 'Appointment not found.' });
    res.json({ message: `Appointment ${status.toLowerCase()}.` });
  });

  app.get('/api/admin/export', auth, adminOnly, adminLimiter, async (_req, res) => {
    const members = await users.find({ role: 'member' }).sort({ createdAt: -1 }).toArray();
    const bs = await bookings.find({}).sort({ createdAt: -1 }).toArray();
    const userMap = new Map(members.map(u => [String(u._id), u]));
    const rows = [['Member ID','Name','Email','Phone','Country','State','Account Status','Member Since','Appointment ID','Service','Preferred Date','Appointment Status','Problem','Admin Note','Appointment Created']];
    for (const m of members) {
      const mine = bs.filter(b => String(b.userId) === String(m._id));
      if (!mine.length) rows.push([m._id,m.name,m.email,m.phone,m.country,m.state,m.status,m.createdAt,'','','','','',m.adminNotes || '','']);
      for (const b of mine) rows.push([m._id,m.name,m.email,m.phone,m.country,m.state,m.status,m.createdAt,b._id,b.service,b.date,b.status,b.problem,b.adminNote,b.createdAt]);
    }
    const csv = rows.map(r => r.map(csvEscape).join(',')).join('\r\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="rebel-ink-members.csv"');
    res.send('\ufeff' + csv);
  });

  // Serve the existing single-page frontend after API routes.
  app.get(/.*/, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

  app.use((err, _req, res, _next) => {
    console.error(err);
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large.' });
    res.status(500).json({ error: 'Server error.' });
  });

  app.listen(PORT, () => console.log(`Rebel Ink server listening on port ${PORT}`));
}

start().catch(err => { console.error('Startup failed:', err); process.exit(1); });
