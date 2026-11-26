// Creates the database + tables, then (only if the database is empty) adds demo data.
//   npm run setup            -> tables + demo data
//   npm run setup -- --empty -> tables only (then register your own owner account at the portal)
require('dotenv').config();
const fs = require('fs'), path = require('path'), mysql = require('mysql2/promise'), bcrypt = require('bcryptjs');
const E = process.env, empty = process.argv.includes('--empty') || E.NODE_ENV === 'production';
(async () => {
  const DB = E.DB_NAME || 'smartboard', cfg = { host: E.DB_HOST || 'localhost', port: +E.DB_PORT || 3306, user: E.DB_USER || 'root', password: E.DB_PASSWORD || '',
    ssl: E.DB_SSL === 'true' ? { minVersion: 'TLSv1.2', rejectUnauthorized: true } : undefined, multipleStatements: true };
  const c = await mysql.createConnection(cfg);
  try { await c.query('CREATE DATABASE IF NOT EXISTS `' + DB + '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'); } catch (e) { /* hosted databases may not allow this - fine if it already exists */ }
  await c.query('USE `' + DB + '`');
  await c.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8').replace(/^\s*CREATE DATABASE[^;]*;/im, '').replace(/^\s*USE [^;]*;/im, ''));
  console.log('Tables ready in database "' + DB + '".');
  const [[{ n }]] = await c.query('SELECT COUNT(*) n FROM rooms');
  if (empty) { console.log('Skipped demo data (--empty).'); return c.end(); }
  if (n > 0) { console.log('Database already has data - demo data skipped.'); return c.end(); }

  const pad = n => String(n).padStart(2, '0'), mo = d => d.getFullYear() + '-' + pad(d.getMonth() + 1), cur = mo(new Date()),
    addm = (m, k) => { const [y, x] = m.split('-').map(Number); return mo(new Date(y, x - 1 + k, 1)); }, r2 = x => Math.round(x * 100) / 100;
  const rooms = [[101, 1, 2500], [102, 1, 2500], [103, 1, 2800], [201, 2, 3000], [202, 2, 3200]];
  for (const [no, f, rent] of rooms) await c.query('INSERT INTO rooms (room_no, floor, rent) VALUES (?,?,?)', [no, f, rent]);
  const rates = [['elec', 12.5, -3], ['water', 30, -3], ['wifi', 100, -3], ['garbage', 50, -3], ['elec', 13.2, -1]].map(([t, v, k]) => [t, v, addm(cur, k)]);
  await c.query('INSERT INTO rates (type, rate_value, effective_month) VALUES ?', [rates]);
  const rate = (t, m) => { const x = rates.filter(r => r[0] === t && r[2] <= m).sort((a, b) => b[2].localeCompare(a[2]))[0]; return x ? x[1] : 0; };

  const names = ['Juan Dela Cruz', 'Maria Santos', 'Pedro Reyes', 'Ana Lim'];
  for (let i = 0; i < 4; i++) {
    const moveIn = addm(cur, -4) + '-05', rent = rooms[i][2];
    const [t] = await c.query('INSERT INTO tenants (name, phone, contact, room_id, move_in) VALUES (?,?,?,?,?)', [names[i], '0917-555-010' + i, 'Family 0918-555-02' + i, i + 1, moveIn]);
    const tid = t.insertId;
    for (const [type, note] of [['deposit', 'Security deposit'], ['advance', 'Advance payment']])
      await c.query('INSERT INTO ledger (tenant_id, bill_month, amount, paid_on, type, note) VALUES (?,?,?,?,?,?)', [tid, moveIn.slice(0, 7), rent, moveIn, type, note]);
    let e = 1000 + i * 200, w = 50 + i * 10;
    for (let k = 3; k >= 1; k--) {
      const m = addm(cur, -k), ce = e + 80 + (i * 7 + k * 13) % 50, cw = w + 6 + (i * 3 + k * 5) % 6;
      await c.query('INSERT INTO readings (room_id, bill_month, prev_elec, curr_elec, prev_water, curr_water) VALUES (?,?,?,?,?,?)', [i + 1, m, e, ce, w, cw]);
      if (!(i === 2 && k === 1)) {   // Pedro hasn't paid last month - shows an overdue example
        const due = r2(rent + r2((ce - e) * rate('elec', m)) + r2((cw - w) * rate('water', m)) + rate('wifi', m) + rate('garbage', m));
        await c.query('INSERT INTO ledger (tenant_id, bill_month, amount, paid_on, type, note) VALUES (?,?,?,?,?,?)', [tid, m, due, m + '-0' + (3 + tid), 'rent', 'Rent & utilities']);
      }
      e = ce; w = cw;
    }
  }
  const users = [['owner', 'owner123', 'Owner Admin', 'owner', null], ['staff', 'staff123', 'Caretaker', 'staff', null], ['tenant', 'tenant123', 'Juan Dela Cruz', 'tenant', 1]];
  for (const [u, p, name, role, tid] of users)
    await c.query('INSERT INTO users (username, password_hash, full_name, role, tenant_id) VALUES (?,?,?,?,?)', [u, bcrypt.hashSync(p, 10), name, role, tid]);
  console.log('Demo data added. Demo logins: owner/owner123, staff/staff123, tenant/tenant123  (remove them before real use!)');
  await c.end();
})().catch(e => { console.error('Setup failed:', e.message); process.exit(1); });