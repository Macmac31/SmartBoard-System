require('dotenv').config();
const path = require('path'), express = require('express'), cors = require('cors'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), helmet = require('helmet'), mysql = require('mysql2/promise'), rateLimit = require('express-rate-limit');
const E = process.env;
if (!E.JWT_SECRET || E.JWT_SECRET.length < 16) { console.error('Missing JWT_SECRET in .env (use 16+ random characters).'); process.exit(1); }
const STAFF_CODE = E.STAFF_CODE || 'SMART2026', PROD = E.NODE_ENV === 'production';
if (PROD && (!E.STAFF_CODE || E.STAFF_CODE === 'SMART2026' || E.STAFF_CODE.length < 8)) {
  console.error('For a public site, set STAFF_CODE to your own secret code (8+ characters, not SMART2026).'); process.exit(1);
}
if (PROD && /change-me/i.test(E.JWT_SECRET)) { console.error('Set a real random JWT_SECRET.'); process.exit(1); }

const pool = mysql.createPool({
  host: E.DB_HOST || 'localhost', port: +E.DB_PORT || 3306, user: E.DB_USER || 'root', password: E.DB_PASSWORD || '',
  database: E.DB_NAME || 'smartboard', charset: 'utf8mb4',
  ssl: E.DB_SSL === 'true' ? { minVersion: 'TLSv1.2', rejectUnauthorized: true } : undefined,   // needed by cloud databases
  waitForConnections: true, connectionLimit: 10,
  decimalNumbers: true,   // DECIMAL columns come back as numbers
  dateStrings: true       // DATE columns come back as 'YYYY-MM-DD'
});
const q = async (sql, p) => (await pool.query(sql, p))[0];
async function tx(fn) { const c = await pool.getConnection(); try { await c.beginTransaction(); const r = await fn(c); await c.commit(); return r; } catch (e) { await c.rollback(); throw e; } finally { c.release(); } }

// ---------- helpers ----------
const bad = (m, c = 400) => Object.assign(new Error(m), { status: c });
const wrap = f => (req, res, next) => Promise.resolve(f(req, res, next)).catch(next);
const isMonth = s => /^\d{4}-(0[1-9]|1[0-2])$/.test(s || '');
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '') && !isNaN(new Date(s + 'T00:00'));
const num = v => (v === '' || v == null) ? NaN : +v;
const money = (v, name = 'Amount') => { const n = num(v); if (!(n >= 0) || n > 1e8) throw bad(name + ' must be a valid number.'); return Math.round(n * 100) / 100; };
const peso = n => '₱' + n.toLocaleString('en-PH', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const today = () => { const d = new Date(), p = n => String(n).padStart(2, '0'); return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()); };
const monthLabel = m => new Date(m + '-15').toLocaleString('en', { month: 'long', year: 'numeric' });
const sign = id => jwt.sign({ id }, E.JWT_SECRET, { expiresIn: '7d' });
const USER = 'SELECT id, username u, full_name n, role r, tenant_id tid FROM users';

// ---------- auth ----------
const auth = wrap(async (req, res, next) => {
  let id;
  try { id = jwt.verify((req.headers.authorization || '').replace(/^Bearer /, ''), E.JWT_SECRET).id; } catch { throw bad('Please log in again.', 401); }
  const [u] = await q(USER + ' WHERE id=?', [id]);   // re-read every time so role changes / removals apply at once
  if (!u) throw bad('Please log in again.', 401);
  req.user = u; next();
});
const need = (...roles) => (req, res, next) => roles.includes(req.user.r) ? next() : next(bad('You do not have permission to do that.', 403));
const STAFF = need('owner', 'staff'), OWNER = need('owner');
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 40, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again in a few minutes.' } });

const app = express();
app.set('trust proxy', 1);                                   // hosts put a proxy in front (correct IPs for rate limiting)
app.use(helmet({ contentSecurityPolicy: false }));
if (!PROD) app.use(cors());                                  // local dev (e.g. VS Code Live Server)
else if (E.CORS_ORIGIN) app.use(cors({ origin: E.CORS_ORIGIN.split(',') }));
app.use(express.json({ limit: '100kb' }));
app.get('/healthz', (req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/login', limiter, wrap(async (req, res) => {
  const u = String(req.body.u || '').trim().toLowerCase(), p = String(req.body.p || '');
  const [row] = await q('SELECT id, password_hash FROM users WHERE username=?', [u]);
  if (!row || !(await bcrypt.compare(p, row.password_hash))) throw bad('Wrong username or password.', 401);
  const [user] = await q(USER + ' WHERE id=?', [row.id]);
  res.json({ token: sign(row.id), user });
}));

app.post('/api/register', limiter, wrap(async (req, res) => {
  const b = req.body, u = String(b.u || '').trim().toLowerCase(), n = String(b.n || '').trim(), r = b.r;
  if (u.length < 3 || u.length > 40) throw bad('Username must be 3-40 characters.');
  if (!n) throw bad('Enter your full name.');
  if (String(b.p || '').length < 6) throw bad('Password must be at least 6 characters.');
  if (b.p !== b.p2) throw bad('Passwords do not match.');
  if (!['tenant', 'staff', 'owner'].includes(r)) throw bad('Choose a valid role.');
  if ((await q('SELECT 1 FROM users WHERE username=?', [u])).length) throw bad('That username is taken. Choose another.');
  let tid = null;
  if (r === 'tenant') {
    const [t] = await q('SELECT t.id FROM tenants t JOIN rooms r ON r.id=t.room_id WHERE r.room_no=? AND t.move_out IS NULL', [String(b.room || '').trim()]);
    if (!t) throw bad('No tenant is checked in to that room. Ask the owner to check you in first.');
    tid = t.id;
  } else if (b.code !== STAFF_CODE) throw bad('Wrong staff / owner access code.');
  const [ins] = await pool.query('INSERT INTO users (username, password_hash, full_name, role, tenant_id) VALUES (?,?,?,?,?)', [u, await bcrypt.hash(b.p, 10), n, r, tid]);
  const [user] = await q(USER + ' WHERE id=?', [ins.insertId]);
  res.status(201).json({ token: sign(ins.insertId), user });
}));

app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

// ---------- the whole picture, filtered by role ----------
const SQL = {
  tenants: "SELECT id, name n, phone ph, contact em, room_id room, move_in `in`, IFNULL(move_out,'') `out` FROM tenants",
  rooms: 'SELECT id, room_no `no`, floor f, rent FROM rooms',
  ledger: 'SELECT id, tenant_id tid, bill_month m, amount a, paid_on d, type t, note FROM ledger',
  readings: 'SELECT room_id room, bill_month m, prev_elec pe, curr_elec ce, prev_water pw, curr_water cw FROM readings',
  misc: 'SELECT id, room_id room, bill_month m, description `desc`, amount a FROM misc_charges',
  rates: 'SELECT id, type t, rate_value v, effective_month e FROM rates',
  exp: 'SELECT id, spent_on d, category cat, description `desc`, amount a FROM expenses ORDER BY spent_on DESC, id DESC'
};
app.get('/api/state', auth, wrap(async (req, res) => {
  const u = req.user, S = { users: [], exp: [] };
  if (u.r !== 'tenant') {
    [S.tenants, S.rooms, S.ledger, S.readings, S.misc] = await Promise.all([
      q(SQL.tenants + ' ORDER BY id'), q(SQL.rooms + ' ORDER BY room_no'), q(SQL.ledger + ' ORDER BY id'), q(SQL.readings), q(SQL.misc + ' ORDER BY id')]);
  } else {   // a tenant only ever receives their own records
    const [me] = await q('SELECT room_id FROM tenants WHERE id=?', [u.tid]), rid = me ? me.room_id : 0;
    [S.tenants, S.rooms, S.ledger, S.readings, S.misc] = await Promise.all([
      q(SQL.tenants + ' WHERE id=?', [u.tid]), q(SQL.rooms + ' WHERE id=?', [rid]), q(SQL.ledger + ' WHERE tenant_id=? ORDER BY id', [u.tid]),
      q(SQL.readings + ' WHERE room_id=?', [rid]), q(SQL.misc + ' WHERE room_id=? ORDER BY id', [rid])]);
  }
  S.rates = await q(SQL.rates);
  if (u.r === 'owner') { S.users = await q(USER + ' ORDER BY id'); S.exp = await q(SQL.exp); }
  res.json(S);
}));

// ---------- tenants ----------
app.post('/api/tenants', auth, STAFF, wrap(async (req, res) => {
  const b = req.body, n = String(b.n || '').trim(), room = +b.room;
  if (!n) throw bad('Enter the tenant name.');
  if (!isDate(b.in)) throw bad('Enter a valid move-in date.');
  if (!(await q('SELECT 1 FROM rooms WHERE id=?', [room])).length) throw bad('Choose a room.');
  if ((await q('SELECT 1 FROM tenants WHERE room_id=? AND move_out IS NULL', [room])).length) throw bad('That room is already occupied.');
  const dep = b.dep === '' || b.dep == null ? 0 : money(b.dep, 'Deposit'), adv = b.adv === '' || b.adv == null ? 0 : money(b.adv, 'Advance');
  const id = await tx(async c => {
    const [r] = await c.query('INSERT INTO tenants (name, phone, contact, room_id, move_in) VALUES (?,?,?,?,?)', [n, String(b.ph || ''), String(b.em || ''), room, b.in]);
    for (const [t, v, note] of [['deposit', dep, 'Security deposit'], ['advance', adv, 'Advance payment']])
      if (v > 0) await c.query('INSERT INTO ledger (tenant_id, bill_month, amount, paid_on, type, note) VALUES (?,?,?,?,?,?)', [r.insertId, b.in.slice(0, 7), v, b.in, t, note]);
    return r.insertId;
  });
  res.status(201).json({ id });
}));

app.put('/api/tenants/:id', auth, STAFF, wrap(async (req, res) => {
  const b = req.body, id = +req.params.id, n = String(b.n || '').trim();
  const [t] = await q("SELECT move_out FROM tenants WHERE id=?", [id]);
  if (!t) throw bad('Tenant not found.', 404);
  if (!n) throw bad('Enter the tenant name.');
  if (!isDate(b.in)) throw bad('Enter a valid move-in date.');
  if (t.move_out && b.in > t.move_out) throw bad('Move-in date cannot be after the check-out date.');
  await q('UPDATE tenants SET name=?, phone=?, contact=?, move_in=? WHERE id=?', [n, String(b.ph || ''), String(b.em || ''), b.in, id]);
  res.json({ ok: true });
}));

app.post('/api/tenants/:id/checkout', auth, STAFF, wrap(async (req, res) => {
  const id = +req.params.id, [t] = await q('SELECT move_out FROM tenants WHERE id=?', [id]);
  if (!t) throw bad('Tenant not found.', 404);
  if (t.move_out) throw bad('This tenant is already checked out.');
  const [{ dep }] = await q("SELECT COALESCE(SUM(CASE type WHEN 'deposit' THEN amount WHEN 'refund' THEN -amount ELSE 0 END),0) dep FROM ledger WHERE tenant_id=?", [id]);
  const x = req.body.deduct === '' || req.body.deduct == null ? 0 : money(req.body.deduct, 'Deduction');
  if (x > dep) throw bad('Deduction must be between 0 and the deposit held.');
  await tx(async c => {
    await c.query('UPDATE tenants SET move_out=? WHERE id=?', [today(), id]);
    if (dep > 0) await c.query('INSERT INTO ledger (tenant_id, bill_month, amount, paid_on, type, note) VALUES (?,?,?,?,?,?)',
      [id, today().slice(0, 7), dep, today(), 'refund', `Check-out: refunded ${peso(dep - x)}, deducted ${peso(x)}`]);
  });
  res.json({ ok: true });
}));

// ---------- rooms ----------
app.post('/api/rooms', auth, OWNER, wrap(async (req, res) => {
  const b = req.body, no = String(b.no || '').trim(), f = Math.trunc(num(b.f));
  if (!no) throw bad('Enter a room number.');
  if (!(f >= 0 && f < 100)) throw bad('Enter a valid floor.');
  if ((await q('SELECT 1 FROM rooms WHERE room_no=?', [no])).length) throw bad('Room number already exists.');
  const [r] = await pool.query('INSERT INTO rooms (room_no, floor, rent) VALUES (?,?,?)', [no, f, money(b.rent, 'Rent')]);
  res.status(201).json({ id: r.insertId });
}));
app.put('/api/rooms/:id', auth, OWNER, wrap(async (req, res) => {
  const [r] = await pool.query('UPDATE rooms SET rent=? WHERE id=?', [money(req.body.rent, 'Rent'), +req.params.id]);
  if (!r.affectedRows) throw bad('Room not found.', 404);
  res.json({ ok: true });
}));

// ---------- meter readings (one per room per month; saving again replaces it) ----------
app.post('/api/readings', auth, STAFF, wrap(async (req, res) => {
  const b = req.body, room = +b.room;
  if (!isMonth(b.m)) throw bad('Choose a valid month.');
  if (!(await q('SELECT 1 FROM rooms WHERE id=?', [room])).length) throw bad('Choose a room.');
  const pe = money(b.pe, 'Previous electricity reading'), ce = money(b.ce, 'Current electricity reading'),
    pw = money(b.pw, 'Previous water reading'), cw = money(b.cw, 'Current water reading');
  if (ce < pe || cw < pw) throw bad('Current reading cannot be lower than the previous reading.');
  await q(`INSERT INTO readings (room_id, bill_month, prev_elec, curr_elec, prev_water, curr_water) VALUES (?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE prev_elec=VALUES(prev_elec), curr_elec=VALUES(curr_elec), prev_water=VALUES(prev_water), curr_water=VALUES(curr_water)`,
    [room, b.m, pe, ce, pw, cw]);
  res.status(201).json({ ok: true });
}));

// ---------- extra charges ----------
app.post('/api/misc', auth, OWNER, wrap(async (req, res) => {
  const b = req.body, d = String(b.desc || '').trim();
  if (!isMonth(b.m)) throw bad('Choose a valid month.');
  if (!d) throw bad('Enter a description.');
  if (!(await q('SELECT 1 FROM rooms WHERE id=?', [+b.room])).length) throw bad('Choose a room.');
  await q('INSERT INTO misc_charges (room_id, bill_month, description, amount) VALUES (?,?,?,?)', [+b.room, b.m, d, money(b.a)]);
  res.status(201).json({ ok: true });
}));
app.delete('/api/misc/:id', auth, OWNER, wrap(async (req, res) => { await q('DELETE FROM misc_charges WHERE id=?', [+req.params.id]); res.json({ ok: true }); }));

// ---------- payments / ledger ----------
app.post('/api/payments', auth, STAFF, wrap(async (req, res) => {
  const b = req.body, tid = +b.tid, a = money(b.a);
  if (!(a > 0)) throw bad('Enter an amount above zero.');
  if (!['rent', 'advance', 'deposit', 'apply'].includes(b.t)) throw bad('Choose a valid payment type.');
  if (!isMonth(b.m)) throw bad('Choose a valid month.');
  if (!isDate(b.d)) throw bad('Enter a valid date.');
  if (!(await q('SELECT 1 FROM tenants WHERE id=?', [tid])).length) throw bad('Choose a tenant.');
  if (b.t === 'apply') {
    const [{ adv }] = await q("SELECT COALESCE(SUM(CASE type WHEN 'advance' THEN amount WHEN 'apply' THEN -amount ELSE 0 END),0) adv FROM ledger WHERE tenant_id=?", [tid]);
    if (a > adv + 0.001) throw bad('That is more than the advance balance.');
  }
  const note = { rent: 'Rent & utilities', advance: 'Advance payment', deposit: 'Security deposit', apply: 'Advance applied to ' + monthLabel(b.m) + ' bill' }[b.t];
  await q('INSERT INTO ledger (tenant_id, bill_month, amount, paid_on, type, note) VALUES (?,?,?,?,?,?)', [tid, b.m, a, b.d, b.t, note]);
  res.status(201).json({ ok: true });
}));

// ---------- expenses ----------
app.post('/api/expenses', auth, OWNER, wrap(async (req, res) => {
  const b = req.body, a = money(b.a), cat = String(b.cat || '').trim();
  if (!(a > 0)) throw bad('Enter an amount above zero.');
  if (!isDate(b.d)) throw bad('Enter a valid date.');
  if (!cat) throw bad('Choose a category.');
  await q('INSERT INTO expenses (spent_on, category, description, amount) VALUES (?,?,?,?)', [b.d, cat, String(b.desc || '').trim(), a]);
  res.status(201).json({ ok: true });
}));
app.delete('/api/expenses/:id', auth, OWNER, wrap(async (req, res) => { await q('DELETE FROM expenses WHERE id=?', [+req.params.id]); res.json({ ok: true }); }));

// ---------- rates ----------
app.post('/api/rates', auth, OWNER, wrap(async (req, res) => {
  const b = req.body;
  if (!['elec', 'water', 'wifi', 'garbage'].includes(b.t)) throw bad('Choose a valid rate type.');
  if (!isMonth(b.e)) throw bad('Choose a valid effective month.');
  await q('INSERT INTO rates (type, rate_value, effective_month) VALUES (?,?,?)', [b.t, money(b.v, 'Rate'), b.e]);
  res.status(201).json({ ok: true });
}));

// ---------- user accounts ----------
app.put('/api/users/:id', auth, OWNER, wrap(async (req, res) => {
  const id = +req.params.id, role = req.body.role, [u] = await q('SELECT id, tenant_id FROM users WHERE id=?', [id]);
  if (!u) throw bad('Account not found.', 404);
  if (id === req.user.id) throw bad("You can't change your own role.");
  if (!['owner', 'staff', 'tenant'].includes(role)) throw bad('Choose a valid role.');
  if (role === 'tenant' && !u.tenant_id) throw bad('A tenant account must be linked to a tenant record. Ask them to register as a tenant with their room number.');
  await q('UPDATE users SET role=? WHERE id=?', [role, id]);
  res.json({ ok: true });
}));
app.delete('/api/users/:id', auth, OWNER, wrap(async (req, res) => {
  if (+req.params.id === req.user.id) throw bad("You can't remove your own account.");
  await q('DELETE FROM users WHERE id=?', [+req.params.id]);
  res.json({ ok: true });
}));

// ---------- errors ----------
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => {
  if (err.status) return res.status(err.status).json({ error: err.message });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Bad request.' });
  if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'That record already exists.' });
  console.error(err); res.status(500).json({ error: 'Server error. Check the server console.' });
});

module.exports = app;   // lets hosts such as Vercel run the app as a function
if (require.main === module) {   // normal start: npm start
  pool.query('SELECT 1').then(() => app.listen(+E.PORT || 3000, () => console.log(`SmartBoard running at http://localhost:${E.PORT || 3000}`)))
    .catch(e => { console.error('Cannot connect to MySQL:', e.message, '\nCheck DB_* in your .env file and that MySQL is running, and that you ran: npm run setup'); process.exit(1); });
}