 const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET;
if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
if (!sessionSecret || sessionSecret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters');
const allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: allowedOrigins.length ? allowedOrigins : false, credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);

// ── SCHEMAS ──
const complaintSchema = new mongoose.Schema({
  trackingId:   { type: String, unique: true },
  fullName:     String,
  phone:        String,
  email:        String,
  title:        String,
  description:  String,
  category:     String,
  county:       String,
  constituency: String,
  ward:         String,
  village:      String,
  attachments:  [{ fileId: mongoose.Schema.Types.ObjectId, filename: String, mimeType: String, size: Number }],
  priority:     { type: String, default: 'medium' },
  status:       { type: String, default: 'pending' },
  assignedTo:   String,
  assignmentNotes: String,
  dueDate:      String,
  resolvedAt:   Date,
}, { timestamps: true });

const bursarySchema = new mongoose.Schema({
  applicationId: { type: String, unique: true },
  studentName:     String,
  idNumber:        String,
  gender:          String,
  dob:             String,
  phone:           String,
  schoolName:      String,
  institutionType: String,
  schoolCounty:    String,
  yearOfStudy:     String,
  admissionNo:     String,
  feeBalance:      Number,
  amountRequested: Number,
  attachments:     [{ fileId: mongoose.Schema.Types.ObjectId, filename: String, mimeType: String, size: Number }],
  guardianName:    String,
  guardianPhone:   String,
  guardianId:      String,
  relationship:    String,
  income:          String,
  reason:          String,
  ward:            String,
  status:          { type: String, default: 'submitted' },
  reviewedBy:      String,
  approvedAmount:  Number,
}, { timestamps: true });

const proposalSchema = new mongoose.Schema({
  proposalId:        { type: String, unique: true },
  title:             String,
  category:          String,
  ward:              String,
  constituency:      String,
  budget:            Number,
  description:       String,
  problemStatement:  String,
  beneficiaries:     Number,
  impactAreas:       [String],
  impactDescription: String,
  priority:          String,
  timeline:          String,
  submittedBy:       String,
  phone:             String,
  proposerEmail:     String,
  proposerRole:      String,
  status:            { type: String, default: 'submitted' },
  reviewNotes:       String,
  convertedTo:       String,
  attachments:       [{ fileId: mongoose.Schema.Types.ObjectId, filename: String, mimeType: String, size: Number }],
}, { timestamps: true });

const projectSchema = new mongoose.Schema({
  projectId:    { type: String, unique: true },
  name:         String,
  category:     String,
  description:  String,
  ward:         String,
  constituency: String,
  department:   String,
  budget:       Number,
  spent:        { type: Number, default: 0 },
  contractor:   String,
  contractorContact: String,
  fundingSource:{ type: String, default: 'NG-CDF' },
  gps:          String,
  startDate:    String,
  endDate:      String,
  progress:     { type: Number, default: 0 },
  status:       { type: String, default: 'planned' },
  publishedToPublic: { type: Boolean, default: false },
}, { timestamps: true });

const staffSchema = new mongoose.Schema({
  employeeId:  { type: String, unique: true },
  fullName:    String,
  department:  String,
  role:        String,
  phone:       String,
  email:       { type: String, unique: true },
  passwordHash:String,
  permission:  { type: String, default: 'staff' },
  status:      { type: String, default: 'active' },
}, { timestamps: true });

const newsSchema = new mongoose.Schema({
  title:       String,
  category:    String,
  summary:     String,
  body:        String,
  tag:         String,
  tags:        [String],
  link:        String,
  publishedBy: String,
  status:      { type: String, enum: ['draft', 'published', 'archived'], default: 'draft' },
  published:   { type: Boolean, default: false },
}, { timestamps: true });

const notificationSchema = new mongoose.Schema({
  message:   String,
  type:      String,
  relatedId: String,
  read:      { type: Boolean, default: false },
}, { timestamps: true });

const adminAccountSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  sessionVersion: { type: Number, default: 0 },
  active: { type: Boolean, default: true },
}, { timestamps: true });

// ── MODELS ──
const Complaint     = mongoose.model('Complaint',     complaintSchema);
const Bursary       = mongoose.model('Bursary',       bursarySchema);
const Proposal      = mongoose.model('Proposal',      proposalSchema);
const Project       = mongoose.model('Project',       projectSchema);
const Staff         = mongoose.model('Staff',         staffSchema);
const News          = mongoose.model('News',          newsSchema);
const Notification  = mongoose.model('Notification',  notificationSchema);
const AdminAccount  = mongoose.model('AdminAccount',  adminAccountSchema);

function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map(item => item.trim().split(/=(.*)/s).slice(0, 2)).filter(([key, value]) => key && value !== undefined).map(([key, value]) => [key, decodeURIComponent(value)]));
}

function signSession(email, sessionVersion = 0) {
  const payload = Buffer.from(JSON.stringify({ email, sessionVersion, exp: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function getSession(req) {
  const token = parseCookies(req.headers.cookie).senatelink_session;
  if (!token) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', sessionSecret).update(payload).digest();
  let supplied;
  try { supplied = Buffer.from(signature, 'base64url'); } catch { return null; }
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.exp > Date.now() ? data : null;
  } catch { return null; }
}

async function requireAdmin(req, res, next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'Authentication required' });
  try {
    const account = await AdminAccount.findOne({ email: session.email, active: true }).select('sessionVersion');
    if (!account || (account.sessionVersion || 0) !== (session.sessionVersion || 0)) return res.status(401).json({ error: 'Admin session expired' });
    req.admin = session;
    next();
  } catch (error) {
    next(error);
  }
}

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false });
const submissionLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false });
const acceptedMimeTypes = new Set([
  'application/pdf',
  'image/jpeg',
  'image/png',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
]);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 4 },
  fileFilter: (req, file, callback) => callback(acceptedMimeTypes.has(file.mimetype) ? null : new Error('Unsupported file type'), acceptedMimeTypes.has(file.mimetype)),
});
let uploadsBucket;

function storeFiles(files, category) {
  if (!files?.length) return Promise.resolve([]);
  return Promise.all(files.map(file => new Promise((resolve, reject) => {
    const stream = uploadsBucket.openUploadStream(file.originalname, {
      contentType: file.mimetype,
      metadata: { category },
    });
    stream.on('error', reject);
    stream.on('finish', () => resolve({ fileId: stream.id, filename: file.originalname, mimeType: file.mimetype, size: file.size }));
    stream.end(file.buffer);
  })));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (error, key) => error ? reject(error) : resolve(`${salt}:${key.toString('hex')}`)));
}

async function verifyPassword(password, stored) {
  const [salt, hash] = (stored || '').split(':');
  if (!salt || !hash) return false;
  const candidate = await hashPassword(password, salt);
  const candidateHash = Buffer.from(candidate.split(':')[1], 'hex');
  const storedHash = Buffer.from(hash, 'hex');
  return candidateHash.length === storedHash.length && crypto.timingSafeEqual(candidateHash, storedHash);
}

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const account = await AdminAccount.findOne({ email, active: true });
    if (!account || !(await verifyPassword(password, account.passwordHash))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    res.cookie('senatelink_session', signSession(account.email, account.sessionVersion || 0), {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000,
      path: '/',
    });
    res.json({ success: true, email: account.email });
  } catch (error) {
    console.error('Admin login failed:', error.message);
    res.status(500).json({ error: 'Unable to sign in' });
  }
});

app.get('/api/auth/session', (req, res) => {
  const session = getSession(req);
  res.json({ authenticated: Boolean(session), email: session?.email || null });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('senatelink_session', { httpOnly: true, secure: isProduction, sameSite: 'strict', path: '/' });
  res.json({ success: true });
});

app.post('/api/auth/change-password', requireAdmin, async (req, res) => {
  try {
    const currentPassword = String(req.body.currentPassword || '');
    const newPassword = String(req.body.newPassword || '');
    if (newPassword.length < 12 || !/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword) || !/[^A-Za-z0-9]/.test(newPassword)) {
      return res.status(400).json({ error: 'New password must be at least 12 characters and include upper/lower case, a number, and a symbol' });
    }
    const account = await AdminAccount.findOne({ email: req.admin.email, active: true });
    if (!account || !(await verifyPassword(currentPassword, account.passwordHash))) return res.status(401).json({ error: 'Current password is incorrect' });
    if (currentPassword === newPassword) return res.status(400).json({ error: 'New password must differ from the current password' });
    account.passwordHash = await hashPassword(newPassword);
    account.sessionVersion = (account.sessionVersion || 0) + 1;
    await account.save();
    res.clearCookie('senatelink_session', { httpOnly: true, secure: isProduction, sameSite: 'strict', path: '/' });
    res.json({ success: true, message: 'Password changed. Sign in again with the new password.' });
  } catch (error) {
    console.error('Admin password change failed:', error.message);
    res.status(500).json({ error: 'Unable to change password' });
  }
});

app.use('/api', (req, res, next) => {
  const isPublicSubmission = req.method === 'POST' && ['/complaints', '/bursary', '/proposals'].includes(req.path);
  const isPublicRead = req.method === 'GET' && ['/projects/public', '/news', '/public/stats'].includes(req.path);
  const isPublicTracking = req.method === 'GET' && req.path.startsWith('/complaints/track/');
  if (isPublicSubmission) return submissionLimiter(req, res, next);
  if (isPublicRead || isPublicTracking) return next();
  return requireAdmin(req, res, next);
});

app.get('/api/public/stats', async (req, res) => {
  try {
    const [totalComplaints, activeProjects, approvedBursaries] = await Promise.all([
      Complaint.countDocuments(),
      Project.countDocuments({ publishedToPublic: true, status: 'active' }),
      Bursary.countDocuments({ status: 'approved' }),
    ]);
    res.set('Cache-Control', 'public, max-age=60');
    res.json({ totalComplaints, activeProjects, approvedBursaries });
  } catch (error) {
    res.status(500).json({ error: 'Public summary is unavailable' });
  }
});

app.get('/api/files/:id', async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'File not found' });
  const fileId = new mongoose.Types.ObjectId(req.params.id);
  const file = await uploadsBucket.find({ _id: fileId }).next();
  if (!file) return res.status(404).json({ error: 'File not found' });
  const safeName = encodeURIComponent(path.basename(file.filename));
  res.set({
    'Content-Type': file.contentType || 'application/octet-stream',
    'Content-Disposition': `attachment; filename*=UTF-8''${safeName}`,
    'X-Content-Type-Options': 'nosniff',
  });
  uploadsBucket.openDownloadStream(fileId).on('error', () => res.destroy()).pipe(res);
});

// ── ID GENERATORS ──
function genId(prefix) {
  return `${prefix}-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
}

// ── HELPER: create notification ──
async function notify(message, type, relatedId = '') {
  await Notification.create({ message, type, relatedId });
}

// ════════════════════════════════
// COMPLAINTS
// ════════════════════════════════
app.post('/api/complaints', upload.single('document'), async (req, res) => {
  try {
    const { fullName, phone, email, title, description, category, county, constituency, ward, village, priority } = req.body;
    if (![fullName, phone, title, description, category, ward].every(value => typeof value === 'string' && value.trim())) {
      return res.status(400).json({ error: 'Please complete all required complaint fields' });
    }
    const trackingId = genId('MSC-CMP');
    const attachments = await storeFiles(req.file ? [req.file] : [], 'complaint');
    const complaint = await Complaint.create({ fullName, phone, email, title, description, category, county, constituency, ward, village, attachments, priority, trackingId });
    await notify(`New complaint from ${ward}: ${title}`, 'complaint', complaint._id);
    res.status(201).json({ success: true, trackingId, complaint });
  } catch (err) { console.error('Complaint submission failed:', err.message); res.status(500).json({ error: 'Unable to submit complaint' }); }
});

app.get('/api/complaints/track/:trackingId', async (req, res) => {
  try {
    const complaint = await Complaint.findOne({ trackingId: req.params.trackingId.toUpperCase() }).select('trackingId status createdAt updatedAt resolvedAt');
    if (!complaint) return res.status(404).json({ error: 'No complaint found for that tracking ID' });
    res.json(complaint);
  } catch (err) { res.status(500).json({ error: 'Unable to check complaint status' }); }
});

app.get('/api/complaints', async (req, res) => {
  try {
    const { status, category, ward, priority } = req.query;
    const filter = {};
    if (status)   filter.status   = status;
    if (category) filter.category = category;
    if (ward)     filter.ward     = ward;
    if (priority) filter.priority = priority;
    const complaints = await Complaint.find(filter).sort({ createdAt: -1 });
    res.json(complaints);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/complaints/:id', async (req, res) => {
  try {
    const c = await Complaint.findById(req.params.id);
    if (!c) return res.status(404).json({ error: 'Not found' });
    res.json(c);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/complaints/:id', async (req, res) => {
  try {
    const allowedStatuses = ['pending', 'in_review', 'assigned', 'resolved', 'escalated'];
    const allowedPriorities = ['low', 'medium', 'normal', 'high', 'urgent', 'critical'];
    const changes = {};
    if (req.body.status !== undefined) {
      if (!allowedStatuses.includes(req.body.status)) return res.status(400).json({ error: 'Unsupported complaint status' });
      changes.status = req.body.status;
      if (req.body.status === 'resolved') changes.resolvedAt = new Date();
    }
    if (req.body.priority !== undefined) {
      if (!allowedPriorities.includes(req.body.priority)) return res.status(400).json({ error: 'Unsupported priority' });
      changes.priority = req.body.priority === 'normal' ? 'medium' : req.body.priority;
    }
    if (req.body.assignedTo !== undefined) changes.assignedTo = String(req.body.assignedTo).trim().slice(0, 120);
    if (req.body.assignmentNotes !== undefined) changes.assignmentNotes = String(req.body.assignmentNotes).slice(0, 1000);
    if (req.body.dueDate !== undefined) changes.dueDate = String(req.body.dueDate).slice(0, 10);
    const updated = await Complaint.findByIdAndUpdate(req.params.id, changes, { new: true, runValidators: true });
    if (!updated) return res.status(404).json({ error: 'Complaint not found' });
    if (req.body.status === 'resolved') {
      await notify(`Complaint ${updated.trackingId} marked resolved`, 'complaint', updated._id);
    }
    if (req.body.assignedTo) {
      await notify(`Complaint ${updated.trackingId} assigned to ${req.body.assignedTo}`, 'complaint', updated._id);
    }
    res.json({ success: true, updated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/complaints/:id', async (req, res) => {
  try {
    await Complaint.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════
// BURSARIES
// ════════════════════════════════
app.post('/api/bursary', upload.array('documents', 4), async (req, res) => {
  try {
    const allowedFields = ['studentName', 'idNumber', 'gender', 'dob', 'phone', 'schoolName', 'institutionType', 'schoolCounty', 'yearOfStudy', 'admissionNo', 'feeBalance', 'amountRequested', 'guardianName', 'guardianPhone', 'guardianId', 'relationship', 'income', 'reason', 'ward'];
    if (!['studentName', 'idNumber', 'schoolName', 'amountRequested', 'guardianName', 'guardianPhone', 'reason', 'ward'].every(key => req.body[key] !== undefined && String(req.body[key]).trim())) {
      return res.status(400).json({ error: 'Please complete all required bursary fields' });
    }
    if ((req.files || []).length < 3) return res.status(400).json({ error: 'Admission, fee, and identity documents are required' });
    const applicationId = genId('BRS-2026');
    const data = Object.fromEntries(allowedFields.filter(key => req.body[key] !== undefined).map(key => [key, req.body[key]]));
    const attachments = await storeFiles(req.files, 'bursary');
    const bursary = await Bursary.create({ ...data, attachments, applicationId });
    await notify(`New bursary application from ${bursary.studentName}`, 'bursary', bursary._id);
    res.status(201).json({ success: true, applicationId, bursary });
  } catch (err) { console.error('Bursary submission failed:', err.message); res.status(500).json({ error: 'Unable to submit bursary application' }); }
});

app.get('/api/bursary', async (req, res) => {
  try {
    const { status, institutionType, ward } = req.query;
    const filter = {};
    if (status)          filter.status          = status;
    if (institutionType) filter.institutionType = institutionType;
    if (ward)            filter.ward            = ward;
    const bursaries = await Bursary.find(filter).sort({ createdAt: -1 });
    res.json(bursaries);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/bursary/:id', async (req, res) => {
  try {
    const b = await Bursary.findById(req.params.id);
    if (!b) return res.status(404).json({ error: 'Not found' });
    res.json(b);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/bursary/:id', async (req, res) => {
  try {
    const allowedStatuses = ['submitted', 'under_review', 'approved', 'rejected', 'on_hold'];
    const changes = {};
    if (req.body.status !== undefined) {
      if (!allowedStatuses.includes(req.body.status)) return res.status(400).json({ error: 'Unsupported bursary status' });
      changes.status = req.body.status;
    }
    if (req.body.reviewedBy !== undefined) changes.reviewedBy = String(req.body.reviewedBy).slice(0, 120);
    if (req.body.approvedAmount !== undefined) {
      const approvedAmount = Number(req.body.approvedAmount);
      if (!Number.isFinite(approvedAmount) || approvedAmount < 0 || approvedAmount > 200000) return res.status(400).json({ error: 'Approved amount must be between KES 0 and 200,000' });
      changes.approvedAmount = approvedAmount;
    }
    const updated = await Bursary.findByIdAndUpdate(req.params.id, changes, { new: true, runValidators: true });
    if (!updated) return res.status(404).json({ error: 'Bursary application not found' });
    if (req.body.status === 'approved') {
      await notify(`Bursary approved for ${updated.studentName}`, 'bursary', updated._id);
    }
    res.json({ success: true, updated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/bursary/:id', async (req, res) => {
  try {
    await Bursary.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════
// PROPOSALS
// ════════════════════════════════
app.post('/api/proposals', upload.array('documents', 3), async (req, res) => {
  try {
    const allowedFields = ['title', 'category', 'ward', 'constituency', 'budget', 'description', 'problemStatement', 'beneficiaries', 'impactAreas', 'impactDescription', 'priority', 'timeline', 'submittedBy', 'phone', 'proposerEmail', 'proposerRole'];
    if (!['title', 'category', 'ward', 'budget', 'description', 'submittedBy', 'phone'].every(key => req.body[key] !== undefined && String(req.body[key]).trim())) {
      return res.status(400).json({ error: 'Please complete all required proposal fields' });
    }
    const proposalId = genId('PRP-2026');
    const data = Object.fromEntries(allowedFields.filter(key => req.body[key] !== undefined).map(key => [key, req.body[key]]));
    if (typeof data.impactAreas === 'string') {
      try { data.impactAreas = JSON.parse(data.impactAreas); } catch { data.impactAreas = []; }
    }
    if (!Array.isArray(data.impactAreas)) data.impactAreas = [];
    const attachments = await storeFiles(req.files, 'proposal');
    const proposal = await Proposal.create({ ...data, attachments, proposalId });
    await notify(`New proposal: ${proposal.title} from ${proposal.ward}`, 'proposal', proposal._id);
    res.status(201).json({ success: true, proposalId, proposal });
  } catch (err) { console.error('Proposal submission failed:', err.message); res.status(500).json({ error: 'Unable to submit proposal' }); }
});

app.get('/api/proposals', async (req, res) => {
  try {
    const { status, category, ward } = req.query;
    const filter = {};
    if (status)   filter.status   = status;
    if (category) filter.category = category;
    if (ward)     filter.ward     = ward;
    const proposals = await Proposal.find(filter).sort({ createdAt: -1 });
    res.json(proposals);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/proposals/:id', async (req, res) => {
  try {
    const p = await Proposal.findById(req.params.id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/proposals/:id', async (req, res) => {
  try {
    const changes = {};
    if (req.body.status !== undefined) {
      if (!['submitted', 'under_review', 'approved', 'rejected', 'forwarded'].includes(req.body.status)) return res.status(400).json({ error: 'Unsupported proposal status' });
      changes.status = req.body.status;
    }
    if (req.body.reviewNotes !== undefined) changes.reviewNotes = String(req.body.reviewNotes).slice(0, 2000);
    const updated = await Proposal.findByIdAndUpdate(req.params.id, changes, { new: true, runValidators: true });
    if (!updated) return res.status(404).json({ error: 'Proposal not found' });
    if (req.body.status === 'approved') {
      await notify(`Proposal approved: ${updated.title}`, 'proposal', updated._id);
    }
    res.json({ success: true, updated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/proposals/:id/convert', async (req, res) => {
  try {
    const proposal = await Proposal.findById(req.params.id);
    if (!proposal) return res.status(404).json({ error: 'Not found' });
    const projectId = genId('PRJ');
    const project = await Project.create({
      projectId,
      name:         proposal.title,
      category:     proposal.category,
      description:  proposal.description,
      ward:         proposal.ward,
      budget:       proposal.budget,
      status:       'planned',
    });
    proposal.status      = 'approved';
    proposal.convertedTo = projectId;
    await proposal.save();
    await notify(`Proposal converted to project: ${proposal.title}`, 'project', project._id);
    res.json({ success: true, project });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/proposals/:id', async (req, res) => {
  try {
    await Proposal.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════
// PROJECTS (Transparency)
// ════════════════════════════════
app.get('/api/projects/public', async (req, res) => {
  try {
    const projects = await Project.find({ publishedToPublic: true }).select('projectId name category description ward constituency department budget spent contractor gps startDate endDate progress status').sort({ createdAt: -1 });
    res.json(projects);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/projects', async (req, res) => {
  try {
    const { status, department, ward } = req.query;
    const filter = {};
    if (status)     filter.status     = status;
    if (department) filter.department = department;
    if (ward)       filter.ward       = ward;
    const projects = await Project.find(filter).sort({ createdAt: -1 });
    res.json(projects);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/projects/:id', async (req, res) => {
  try {
    const p = await Project.findById(req.params.id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/projects', async (req, res) => {
  try {
    const allowedFields = ['name', 'category', 'description', 'ward', 'constituency', 'department', 'budget', 'spent', 'contractor', 'contractorContact', 'fundingSource', 'gps', 'startDate', 'endDate', 'progress', 'status'];
    if (!['name', 'category', 'description', 'ward', 'budget'].every(key => req.body[key] !== undefined && String(req.body[key]).trim())) return res.status(400).json({ error: 'Project name, category, description, ward, and budget are required' });
    const data = Object.fromEntries(allowedFields.filter(key => req.body[key] !== undefined).map(key => [key, req.body[key]]));
    const budget = Number(data.budget);
    const progress = Number(data.progress || 0);
    if (!Number.isFinite(budget) || budget <= 0 || !Number.isFinite(progress) || progress < 0 || progress > 100) return res.status(400).json({ error: 'Budget or progress value is invalid' });
    const projectId = genId('PRJ');
    const project = await Project.create({ ...data, budget, progress, projectId, publishedToPublic: false });
    await notify(`New project created: ${req.body.name}`, 'project', project._id);
    res.status(201).json({ success: true, project });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/projects/:id', async (req, res) => {
  try {
    const allowedFields = ['name', 'category', 'description', 'ward', 'constituency', 'department', 'budget', 'spent', 'contractor', 'contractorContact', 'fundingSource', 'gps', 'startDate', 'endDate', 'progress', 'status'];
    const changes = Object.fromEntries(allowedFields.filter(key => req.body[key] !== undefined).map(key => [key, req.body[key]]));
    if (changes.status !== undefined && !['planned', 'active', 'completed', 'delayed', 'suspended', 'stalled', 'cancelled'].includes(changes.status)) return res.status(400).json({ error: 'Unsupported project status' });
    for (const field of ['budget', 'spent', 'progress']) {
      if (changes[field] === undefined) continue;
      changes[field] = Number(changes[field]);
      if (!Number.isFinite(changes[field]) || changes[field] < 0 || (field === 'progress' && changes[field] > 100)) return res.status(400).json({ error: `Invalid ${field} value` });
    }
    const updated = await Project.findByIdAndUpdate(req.params.id, changes, { new: true, runValidators: true });
    if (!updated) return res.status(404).json({ error: 'Project not found' });
    if (req.body.progress) {
      await notify(`Project ${updated.name} updated to ${req.body.progress}%`, 'project', updated._id);
    }
    res.json({ success: true, updated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/projects/:id/publish', async (req, res) => {
  try {
    const updated = await Project.findByIdAndUpdate(req.params.id, { publishedToPublic: true }, { new: true });
    res.json({ success: true, updated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/projects/:id', async (req, res) => {
  try {
    await Project.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════
// STAFF
// ════════════════════════════════
app.post('/api/staff', async (req, res) => {
  try {
    const { fullName, department, role, phone, email, password, permission, status } = req.body;
    if (![fullName, email, role, password].every(value => typeof value === 'string' && value.trim()) || password.length < 12) {
      return res.status(400).json({ error: 'Name, email, role, and a password of at least 12 characters are required' });
    }
    if (!['Super Admin', 'Officer', 'Moderator', 'Editor', 'Viewer'].includes(role) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid staff role or email address' });
    if (status && !['active', 'suspended', 'pending'].includes(status)) return res.status(400).json({ error: 'Unsupported staff status' });
    const employeeId = genId('STF');
    const staff = await Staff.create({ fullName: fullName.trim().slice(0, 120), department: String(department || '').slice(0, 120), role, phone: String(phone || '').slice(0, 30), email: email.trim().toLowerCase(), permission: role, status, passwordHash: await hashPassword(password), employeeId });
    await notify(`New staff account created: ${staff.fullName}`, 'staff', staff._id);
    res.status(201).json({ success: true, employeeId, staff: await Staff.findById(staff._id).select('-passwordHash -password') });
  } catch (err) { console.error('Staff account creation failed:', err.message); res.status(500).json({ error: 'Unable to create staff account' }); }
});

app.get('/api/staff', async (req, res) => {
  try {
    const { department, status } = req.query;
    const filter = {};
    if (department) filter.department = department;
    if (status)     filter.status     = status;
    const staff = await Staff.find(filter).select('-passwordHash -password').sort({ createdAt: -1 });
    res.json(staff);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/staff/:id', async (req, res) => {
  try {
    const allowedFields = ['fullName', 'department', 'role', 'phone', 'email', 'permission', 'status'];
    const changes = Object.fromEntries(allowedFields.filter(key => req.body[key] !== undefined).map(key => [key, req.body[key]]));
    if (changes.role !== undefined && !['Super Admin', 'Officer', 'Moderator', 'Editor', 'Viewer'].includes(changes.role)) return res.status(400).json({ error: 'Unsupported staff role' });
    if (changes.status !== undefined && !['active', 'suspended', 'pending'].includes(changes.status)) return res.status(400).json({ error: 'Unsupported staff status' });
    if (req.body.password) {
      if (String(req.body.password).length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });
      changes.passwordHash = await hashPassword(String(req.body.password));
    }
    const updated = await Staff.findByIdAndUpdate(req.params.id, changes, { new: true, runValidators: true }).select('-passwordHash -password');
    if (!updated) return res.status(404).json({ error: 'Staff account not found' });
    res.json({ success: true, updated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/staff/:id', async (req, res) => {
  try {
    await Staff.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════
// NEWS
// ════════════════════════════════
app.post('/api/news', async (req, res) => {
  try {
    const { title, category, summary, body, tags, publishedBy, status } = req.body;
    if (![title, category, body].every(value => typeof value === 'string' && value.trim())) return res.status(400).json({ error: 'Title, category, and article content are required' });
    if (!['draft', 'published', 'archived'].includes(status || 'draft')) return res.status(400).json({ error: 'Unsupported article status' });
    const news = await News.create({ title, category, summary, body, tags: Array.isArray(tags) ? tags : [], tag: category, publishedBy, status: status || 'draft', published: status === 'published' });
    res.status(201).json({ success: true, news });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/news/admin', async (req, res) => {
  try {
    const news = await News.find().sort({ createdAt: -1 });
    res.json(news);
  } catch (err) { res.status(500).json({ error: 'Unable to load articles' }); }
});

app.get('/api/news', async (req, res) => {
  try {
    const news = await News.find({ published: true, $or: [{ status: 'published' }, { status: { $exists: false } }] }).select('title category summary body createdAt').sort({ createdAt: -1 }).limit(10);
    res.json(news);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/news/:id', async (req, res) => {
  try {
    const { title, category, summary, body, tags, publishedBy, status } = req.body;
    const updated = await News.findByIdAndUpdate(req.params.id, { title, category, summary, body, tags, tag: category, publishedBy, status, published: status === 'published' }, { new: true, runValidators: true });
    res.json({ success: true, updated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/news/:id', async (req, res) => {
  try {
    await News.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════
// NOTIFICATIONS
// ════════════════════════════════
app.get('/api/notifications', async (req, res) => {
  try {
    const notifs = await Notification.find().sort({ createdAt: -1 }).limit(50);
    res.json(notifs);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/notifications/:id/read', async (req, res) => {
  try {
    await Notification.findByIdAndUpdate(req.params.id, { read: true });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/notifications/read-all', async (req, res) => {
  try {
    await Notification.updateMany({ read: false }, { read: true });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/notifications/:id', async (req, res) => {
  try {
    const notification = await Notification.findByIdAndDelete(req.params.id);
    if (!notification) return res.status(404).json({ error: 'Notification not found' });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Unable to delete notification' }); }
});

// ════════════════════════════════
// STATS
// ════════════════════════════════
app.get('/api/stats', async (req, res) => {
  try {
    const [
      totalComplaints, pendingComplaints, resolvedComplaints,
      totalBursaries, approvedBursaries, pendingBursaries, totalProposals,
      activeProjects, totalProjects, totalStaff, totalNews,
      unreadNotifications
    ] = await Promise.all([
      Complaint.countDocuments(),
      Complaint.countDocuments({ status: 'pending' }),
      Complaint.countDocuments({ status: 'resolved' }),
      Bursary.countDocuments(),
      Bursary.countDocuments({ status: 'approved' }),
      Bursary.countDocuments({ status: { $in: ['submitted', 'under_review'] } }),
      Proposal.countDocuments(),
      Project.countDocuments({ status: 'active' }),
      Project.countDocuments(),
      Staff.countDocuments({ status: 'active' }),
      News.countDocuments(),
      Notification.countDocuments({ read: false }),
    ]);
    const complaintsByCategory = await Complaint.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 4 },
    ]);
    res.json({
      totalComplaints, pendingComplaints, resolvedComplaints,
      totalBursaries, approvedBursaries, pendingBursaries,
      totalProposals, activeProjects, totalProjects, totalStaff, totalNews,
      unreadNotifications, complaintsByCategory,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Serve both app folders from the API's public directory through one origin.
const publicRoot = path.join(__dirname, 'public');
app.use('/publicSENATE', express.static(path.join(publicRoot, 'publicSENATE'), { extensions: ['html'] }));
app.use('/admin', express.static(path.join(publicRoot, 'admin'), { extensions: ['html'] }));
app.get('/', (req, res) => res.redirect('/publicSENATE/'));
app.get('/healthz', (req, res) => {
  const ready = mongoose.connection.readyState === 1;
  res.status(ready ? 200 : 503).json({ status: ready ? 'ok' : 'database unavailable' });
});

app.use((error, req, res, next) => {
  console.error('Request failed:', error.message);
  const clientError = error instanceof multer.MulterError || error.message === 'Unsupported file type';
  res.status(clientError ? 400 : error.status || 500).json({ error: clientError ? error.message : 'An unexpected server error occurred' });
});

async function start() {
  await mongoose.connect(process.env.MONGO_URI);
  uploadsBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: 'senatelinkFiles' });
  const port = Number(process.env.PORT) || 8080;
  app.listen(port, () => console.log(`SenateLink server listening on port ${port}`));
}

start().catch(error => {
  console.error('Server startup failed:', error.message);
  process.exit(1);
});