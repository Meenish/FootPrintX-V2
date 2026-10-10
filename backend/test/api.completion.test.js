import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import ExcelJS from 'exceljs';
import { startTestApp, registerAndLogin, connectSyntheticAndScan } from './helpers.js';
import { setMailTransport, sendEmail, updatePreferences } from '../src/services/notifications.js';
import { safeCell } from '../src/services/reports.js';
import { decrypt } from '../src/crypto.js';

let t;
before(async () => { t = await startTestApp({ SMTP_HOST: 'smtp.test', SMTP_FROM: 'noreply@example.com', CONTACT_TO: 'support@example.com' }); });
after(async () => { setMailTransport(null); await t.close(); });

test('Excel report is a real workbook, scoped to its owner, including empty accounts', async () => {
  const { client } = await registerAndLogin(t);
  await client.post('/api/accounts', { serviceName: '=HYPERLINK("https://evil.invalid")', domain: 'private.example.com' });
  const response = await client.get('/api/reports/security.xlsx', { raw: true });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /spreadsheetml/);
  const book = new ExcelJS.Workbook();
  await book.xlsx.load(Buffer.from(await response.arrayBuffer()));
  assert.deepEqual(book.worksheets.map((s) => s.name), ['Summary','Accounts','Risk Findings','Recommendations','DASI History','Security Activity']);
  assert.equal(book.getWorksheet('Accounts').getCell('A2').type, ExcelJS.ValueType.String);
  assert.match(book.getWorksheet('Accounts').getCell('A2').value, /^'=/);
  const other = await registerAndLogin(t);
  const empty = await other.client.get('/api/reports/security.xlsx', { raw: true });
  const otherBook = new ExcelJS.Workbook();
  await otherBook.xlsx.load(Buffer.from(await empty.arrayBuffer()));
  assert.equal(otherBook.getWorksheet('Accounts').getCell('A2').value, 'No records available');
  assert.equal((await t.client().get('/api/reports/security.xlsx')).status, 401);
  for (const s of ['=1+1',' +SUM(A1)','\t@attack','-42']) assert.ok(safeCell(s).startsWith("'"));
});

test('account awareness enforces Premium and ownership, normalizes domains and never infers login', async () => {
  const a = await registerAndLogin(t);
  const b = await registerAndLogin(t);
  await a.client.post('/api/accounts', { domain: 'example.com', serviceName: 'Example' });
  await a.client.post('/api/accounts', { domain: 'alice.github.io', serviceName: 'Tenant' });
  const link = async (client) => {
    const code = (await client.post('/api/extension/link-codes')).body.code;
    const token = (await t.client().post('/api/extension/link', { code })).body.token;
    return { headers: { authorization: `Bearer ${token}` } };
  };
  const opts = await link(a.client);
  const ask = (domain, options = opts, extra = {}) => t.client().post('/api/extension/account-awareness', { domain, ...extra }, options);
  assert.equal((await ask('example.com')).status, 402);
  await a.client.post('/api/billing/dev-checkout');
  const found = await ask('https://LOGIN.Example.com:443/a?q=secret');
  assert.equal(found.status, 200);
  assert.equal(found.body.state, 'account_known');
  assert.equal(found.body.login.state, 'unavailable');
  assert.ok(!JSON.stringify(found.body).includes('secret'));
  assert.equal((await ask('example.com.attacker.invalid')).body.state, 'no_match');
  assert.equal((await ask('bob.github.io')).body.state, 'no_match');
  assert.equal((await ask('alice.github.io')).body.state, 'account_known');
  assert.equal((await ask('javascript:alert(1)')).status, 400);
  assert.equal((await ask('localhost')).status, 400);
  assert.equal((await ask('example.com', opts, { userId: b.user.id })).status, 400);
  await b.client.post('/api/billing/dev-checkout');
  assert.equal((await ask('example.com', await link(b.client))).body.state, 'no_match');
  const accounts = (await a.client.get('/api/accounts')).body.items;
  const id = accounts.find((x) => x.service_domain === 'example.com').id;
  await a.client.patch(`/api/accounts/${id}`, { action: 'dismiss', reason: 'not_mine' });
  assert.equal((await ask('example.com')).body.state, 'no_match');
  await a.client.post('/api/billing/dev-expire');
  assert.equal((await ask('example.com')).status, 402);
});

test('contact validates, encrypts, exports, and only reports SMTP acceptance', async () => {
  const { client, user } = await registerAndLogin(t);
  const body = { name: 'Test user', email: 'reply@example.com', message: 'Please help me understand my account.' };
  assert.equal((await client.post('/api/contact', { ...body, email: 'bad' })).status, 400);
  assert.equal((await t.client().post('/api/contact', body)).status, 401);
  let captured;
  setMailTransport({ sendMail: async (message) => { captured = message; return { accepted: ['support@example.com'], rejected: [] }; } });
  const result = await client.post('/api/contact', body);
  assert.equal(result.status, 201);
  assert.equal(captured.replyTo, body.email);
  const row = (await t.db.query('SELECT * FROM contact_submissions WHERE user_id=$1', [user.id]))[0];
  assert.equal(row.status, 'accepted');
  assert.ok(!JSON.stringify(row.content_enc).includes(body.message));
  assert.equal(JSON.parse(decrypt(row.content_enc, `contact:${row.id}`)).message, body.message);
  const exported = await client.get('/api/privacy/export');
  assert.equal(exported.body.contacts[0].message, body.message);
  setMailTransport({ sendMail: async () => ({ accepted: [], rejected: ['support@example.com'] }) });
  assert.equal((await client.post('/api/contact', body)).status, 502);
  setMailTransport({ sendMail: async () => { throw new Error('SMTP down'); } });
  assert.equal((await client.post('/api/contact', body)).status, 502);
  assert.equal((await client.get('/api/notifications/preferences')).body.preferences.security_alerts_email, false);
});

test('report with discovered evidence contains DASI and recommendations', async () => {
  const { client } = await registerAndLogin(t);
  await connectSyntheticAndScan(client);
  const response = await client.get('/api/reports/security.xlsx', { raw: true });
  const book = new ExcelJS.Workbook();
  await book.xlsx.load(Buffer.from(await response.arrayBuffer()));
  assert.ok(book.getWorksheet('Accounts').rowCount > 5);
  assert.ok(book.getWorksheet('Recommendations').rowCount > 2);
  assert.ok(book.getWorksheet('DASI History').rowCount >= 2);
});

test('notification sends are claimed once; pre-acceptance failures retry but ambiguous failures do not', async () => {
  const { user } = await registerAndLogin(t);
  await updatePreferences(user.id, { security_alerts_email: true });
  let calls = 0;
  setMailTransport({ sendMail: async () => {
    calls++;
    if (calls < 3) throw Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED' });
    return { accepted: ['test@example.com'], rejected: [] };
  } });
  const message = { category: 'security_alerts', dedupKey: 'concurrent', subject: 'Fixture', text: 'Fixture' };
  const results = await Promise.all([sendEmail(user.id, message), sendEmail(user.id, message)]);
  assert.equal(calls, 3);
  assert.equal(results.filter((r) => r.status === 'sent').length, 1);
  assert.equal(results.filter((r) => r.reason === 'duplicate').length, 1);
  calls = 0;
  setMailTransport({ sendMail: async () => { calls++; throw Object.assign(new Error('ambiguous timeout'), { code: 'ETIMEDOUT' }); } });
  assert.equal((await sendEmail(user.id, { ...message, dedupKey: 'timeout' })).status, 'failed');
  assert.equal(calls, 1);
});
