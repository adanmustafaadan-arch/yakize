const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const crypto = require('crypto');
const fs = require('fs');
const mongoose = require('mongoose');

const envPath = path.join(__dirname, '.env');

function derivePassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, key) => error ? reject(error) : resolve(key.toString('hex')));
  });
}

async function setup() {
  if (!process.env.MONGO_URI) throw new Error('Set MONGO_URI in my-api/.env before running setup-admin');
  if (!process.env.SESSION_SECRET) {
    if (process.env.NODE_ENV === 'production') throw new Error('Set SESSION_SECRET in the production environment first');
    const secret = crypto.randomBytes(48).toString('base64url');
    fs.appendFileSync(envPath, `${fs.existsSync(envPath) && fs.statSync(envPath).size ? '\n' : ''}SESSION_SECRET=${secret}\n`, { mode: 0o600 });
    process.env.SESSION_SECRET = secret;
  }

  await mongoose.connect(process.env.MONGO_URI);
  const AdminAccount = mongoose.model('AdminAccount', new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    active: { type: Boolean, default: true },
  }, { timestamps: true }));

  if (await AdminAccount.exists({})) throw new Error('An admin account already exists; refusing to replace credentials');
  const email = (process.env.ADMIN_EMAIL || 'admin@senatelink.local').trim().toLowerCase();
  const password = crypto.randomBytes(32).toString('base64url');
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = `${salt}:${await derivePassword(password, salt)}`;
  await AdminAccount.create({ email, passwordHash });
  console.log(`Initial admin account created.\nEmail: ${email}\nPassword: ${password}\nSave this password now; it will not be displayed again.`);
}

setup().catch(error => {
  console.error(`Admin setup failed: ${error.message}`);
  process.exitCode = 1;
}).finally(async () => {
  if (mongoose.connection.readyState) await mongoose.disconnect();
});