// Notification preferences, unsubscribe, privacy (export / delete).
import { Router } from 'express';
import { z } from 'zod';
import { ah, validate, HttpError } from '../http.js';
import { limits, requireAuth, clearSessionCookies } from '../middleware.js';
import { getPreferences, updatePreferences, verifyUnsubscribeToken, EMAIL_CATEGORIES } from '../services/notifications.js';
import { exportUserData, deleteUserAccount } from '../services/privacy.js';
import { verifyPasswordForUser } from '../services/auth.js';
import { RETENTION } from '../services/maintenance.js';
import { audit } from '../services/audit.js';
import { getConfig } from '../config.js';
import { query, queryOne } from '../db.js';

import { createReport } from '../services/reports.js';
import { submitContact } from '../services/contact.js';

const web = requireAuth({ kinds: ['web'] });
export const settingsRouter = Router();
settingsRouter.get('/reports/security.xlsx', web, limits.sensitive, ah(async (req, res) => {
  const data = await createReport(req.user.id);
  res.type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="footprintx-security-report.xlsx"');
  res.send(Buffer.from(data));
}));
settingsRouter.post('/contact', web, limits.contact, validate({ body: z.object({
  name: z.string().trim().min(1).max(100).regex(/^[^\r\n]+$/),
  email: z.string().trim().email().max(254),
  message: z.string().trim().min(10).max(5000),
}).strict() }), ah(async (req, res) => res.status(201).json(await submitContact(req.user.id, req.body))));


settingsRouter.get('/notifications/preferences', web, ah(async (req, res) => {
  res.json({ preferences: await getPreferences(req.user.id), emailDeliveryConfigured: getConfig().smtp.configured, essentialNote: 'Password-reset and other essential account messages are always sent; they are not marketing and cannot be turned off.' });
}));

settingsRouter.patch('/notifications/preferences', web, validate({
  body: z.object({
    security_alerts_email: z.boolean().optional(),
    remediation_reminders_email: z.boolean().optional(),
    periodic_summary_email: z.boolean().optional(),
    product_updates_email: z.boolean().optional(),
  }).strict(),
}), ah(async (req, res) => {
  const prefs = await updatePreferences(req.user.id, req.body);
  await audit('notification_preferences_updated', { userId: req.user.id, req, detail: req.body });
  res.json({ preferences: prefs });
}));

settingsRouter.get('/notifications/deliveries', web, ah(async (req, res) => {
  res.json({ items: await query('SELECT category, status, reason, created_at FROM notification_deliveries WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50', [req.user.id]) });
}));

// Works without signing in (link from an email); authenticated by an HMAC token.
settingsRouter.post('/notifications/unsubscribe', limits.sensitive, validate({
  body: z.object({ u: z.string().uuid(), c: z.enum(Object.keys(EMAIL_CATEGORIES)), t: z.string().regex(/^[0-9a-f]{64}$/) }).strict(),
}), ah(async (req, res) => {
  if (!verifyUnsubscribeToken(req.body.u, req.body.c, req.body.t)) throw new HttpError(400, 'INVALID_LINK', 'This unsubscribe link is invalid.');
  const exists = await queryOne('SELECT 1 AS x FROM users WHERE id = $1', [req.body.u]);
  if (exists) await updatePreferences(req.body.u, { [EMAIL_CATEGORIES[req.body.c]]: false });
  res.json({ ok: true, category: req.body.c });
}));

settingsRouter.get('/privacy/export', web, limits.sensitive, ah(async (req, res) => {
  const data = await exportUserData(req.user.id);
  await audit('data_exported', { userId: req.user.id, req });
  res.setHeader('Content-Disposition', `attachment; filename="footprintx-export-${new Date().toISOString().slice(0, 10)}.json"`);
  res.json(data);
}));

settingsRouter.get('/privacy/retention', (req, res) => res.json({ retentionDays: RETENTION }));

settingsRouter.delete('/account', web, limits.sensitive, validate({ body: z.object({ password: z.string().min(1).max(128), confirm: z.literal('DELETE') }).strict() }), ah(async (req, res) => {
  if (!(await verifyPasswordForUser(req.user.id, req.body.password))) throw new HttpError(400, 'INVALID_CREDENTIALS', 'Your password is incorrect.');
  const out = await deleteUserAccount(req.user.id);
  clearSessionCookies(res);
  res.json({ deleted: true, googleTokenRevocations: out.revocations, backupsNote: 'Data is removed from the live database now. Encrypted backups expire on the documented backup retention schedule.' });
}));
