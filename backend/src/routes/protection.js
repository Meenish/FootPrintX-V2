// Website reputation, browser-extension APIs and plans/billing.
import { Router } from 'express';
import { z } from 'zod';
import { ah, validate, notFound } from '../http.js';
import { limits, requireAuth, requireAdmin } from '../middleware.js';
import { EXTENSION_EVENT_TYPES } from '@footprintx/shared/threat';
import { checkDomain, datasetStatus, lookupPrefixes, reportFalsePositive, syncAllFeeds } from '../services/reputation.js';
import { createLinkCode, linkExtension, extensionStatus, setExtensionSync, ingestEvents, listExtensionSessions, unlinkExtensionSession, listExtensionEvents } from '../services/extension.js';
import { getPackage, packageStatus, TARGETS } from '../services/extensionPackage.js';
import { planCatalog, getEntitlement, requirePremium, devCheckout, cancelSubscription, resumeSubscription, devExpire } from '../services/billing.js';
import { revokeSession } from '../services/auth.js';
import { audit } from '../services/audit.js';
import { query } from '../db.js';

import { accountAwareness } from '../services/awareness.js';

const web = requireAuth({ kinds: ['web'] });
const ext = requireAuth({ kinds: ['extension'] });
const webOrExt = requireAuth({ kinds: ['web', 'extension'] });

export const protectionRouter = Router();
protectionRouter.post('/extension/account-awareness', ext, limits.extensionLookup, validate({ body: z.object({ domain: z.string().min(1).max(253) }).strict() }), ah(async (req,res) => {
  await requirePremium(req.user.id);
  res.json(await accountAwareness(req.user.id, req.body.domain));
}));


// ---- Reputation -------------------------------------------------------------------------
protectionRouter.post('/reputation/check', webOrExt, limits.manualReputation, validate({ body: z.object({ domain: z.string().trim().min(1).max(2048) }).strict() }), ah(async (req, res) => {
  res.json(await checkDomain(req.user.id, req.body.domain));
}));
protectionRouter.get('/reputation/dataset', webOrExt, ah(async (req, res) => res.json(await datasetStatus())));
protectionRouter.post('/reputation/false-positive', webOrExt, limits.sensitive, validate({ body: z.object({ domain: z.string().max(253), reportedStatus: z.enum(['malicious', 'suspicious']), note: z.string().max(500).optional() }).strict() }), ah(async (req, res) => {
  await reportFalsePositive(req.user.id, req.body);
  res.status(201).json({ ok: true, message: 'Thanks — the report was recorded for review. FootprintX does not change listings automatically.' });
}));

// ---- Extension: web-app side ----------------------------------------------------------
// Download is available to Free users too: installing the extension and seeing
// its status and upgrade path is not a paid capability (docs/PLANS.md). Active
// protection is gated server-side in /extension/lookup.
protectionRouter.get('/extension/package', web, ah(async (req, res) => res.json(await packageStatus())));

protectionRouter.get('/extension/package/:target', web, limits.sensitive, validate({ params: z.object({ target: z.enum(Object.keys(TARGETS)) }) }), ah(async (req, res) => {
  const pkg = await getPackage(req.params.target);
  await audit('extension_package_downloaded', { userId: req.user.id, req, detail: { target: req.params.target } });
  res.type('application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${pkg.filename}"`);
  res.setHeader('Content-Length', String(pkg.size));
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(pkg.path);
}));

protectionRouter.post('/extension/link-codes', web, limits.sensitive, ah(async (req, res) => {
  const out = await createLinkCode(req.user.id);
  await audit('extension_link_code_created', { userId: req.user.id, req });
  res.status(201).json(out);
}));
protectionRouter.get('/extension/devices', web, ah(async (req, res) => res.json({ items: await listExtensionSessions(req.user.id) })));
protectionRouter.delete('/extension/devices/:id', web, validate({ params: z.object({ id: z.string().uuid() }) }), ah(async (req, res) => {
  if (!(await unlinkExtensionSession(req.user.id, req.params.id))) throw notFound('Linked browser');
  await audit('extension_unlinked', { userId: req.user.id, req });
  res.status(204).end();
}));
protectionRouter.get('/extension/events', web, ah(async (req, res) => {
  const ent = await getEntitlement(req.user.id);
  res.json({ items: await listExtensionEvents(req.user.id, { days: ent.features.advancedHistoryDays }) });
}));
protectionRouter.delete('/extension/events', web, ah(async (req, res) => {
  const rows = await query('DELETE FROM extension_events WHERE user_id = $1 RETURNING id', [req.user.id]);
  await audit('extension_events_deleted', { userId: req.user.id, req, detail: { count: rows.length } });
  res.json({ deleted: rows.length });
}));

// ---- Extension: extension side (Bearer token) -------------------------------------------
protectionRouter.post('/extension/link', limits.extensionLink, validate({ body: z.object({ code: z.string().min(6).max(20), label: z.string().max(60).optional() }).strict() }), ah(async (req, res) => {
  const out = await linkExtension(req.body.code, req.body.label);
  await audit('extension_linked', { userId: out.userId, sessionId: out.sessionId, req });
  res.status(201).json({ token: out.token, expiresAt: out.expiresAt });
}));
protectionRouter.get('/extension/status', ext, ah(async (req, res) => res.json(await extensionStatus(req.auth))));
protectionRouter.post('/extension/unlink', ext, ah(async (req, res) => {
  await revokeSession(req.auth.session.id, req.user.id);
  await audit('extension_unlinked', { userId: req.user.id, req, detail: { by: 'extension' } });
  res.status(204).end();
}));
protectionRouter.put('/extension/settings', ext, validate({ body: z.object({ syncEnabled: z.boolean() }).strict() }), ah(async (req, res) => {
  const out = await setExtensionSync(req.auth, req.body.syncEnabled);
  await audit('extension_sync_changed', { userId: req.user.id, req, detail: out });
  res.json(out);
}));
// Premium: automatic checks. Only hash prefixes arrive here — never URLs or hostnames.
protectionRouter.post('/extension/lookup', ext, limits.extensionLookup, validate({ body: z.object({ prefixes: z.array(z.string()).min(1).max(10) }).strict() }), ah(async (req, res) => {
  const ent = await requirePremium(req.user.id);
  res.json({ ...(await lookupPrefixes(req.body.prefixes)), entitlement: { plan: ent.plan, state: ent.state } });
}));
protectionRouter.post('/extension/events', ext, limits.extensionEvents, validate({
  body: z.object({
    events: z.array(z.object({
      clientEventId: z.string().uuid(),
      type: z.enum(EXTENSION_EVENT_TYPES),
      domain: z.string().min(1).max(253),
      status: z.enum(['malicious', 'suspicious']),
      reasonCodes: z.array(z.string().regex(/^[A-Z_]{2,40}$/)).max(10).optional(),
      datasetVersion: z.string().max(60).optional(),
      occurredAt: z.string().datetime(),
    }).strict()).min(1).max(20),
  }).strict(),
}), ah(async (req, res) => {
  const out = await ingestEvents(req.auth, req.body.events);
  res.status(202).json(out);
}));

// ---- Plans & billing -----------------------------------------------------------------------
protectionRouter.get('/billing', web, ah(async (req, res) => res.json({ catalog: planCatalog(), entitlement: await getEntitlement(req.user.id) })));
protectionRouter.post('/billing/dev-checkout', web, limits.sensitive, ah(async (req, res) => {
  const ent = await devCheckout(req.user.id);
  await audit('subscription_dev_checkout', { userId: req.user.id, req });
  res.json({ entitlement: ent, paymentProcessed: false, notice: planCatalog().developmentNotice });
}));
protectionRouter.post('/billing/cancel', web, limits.sensitive, ah(async (req, res) => {
  const ent = await cancelSubscription(req.user.id);
  await audit('subscription_canceled', { userId: req.user.id, req });
  res.json({ entitlement: ent });
}));
protectionRouter.post('/billing/resume', web, ah(async (req, res) => res.json({ entitlement: await resumeSubscription(req.user.id) })));
protectionRouter.post('/billing/dev-expire', web, ah(async (req, res) => {
  const ent = await devExpire(req.user.id);
  await audit('subscription_dev_expired', { userId: req.user.id, req });
  res.json({ entitlement: ent });
}));

// ---- Admin ---------------------------------------------------------------------------------
protectionRouter.post('/admin/threat-sync', web, requireAdmin, ah(async (req, res) => {
  const results = await syncAllFeeds();
  await audit('threat_sync_manual', { userId: req.user.id, req });
  res.json({ results, dataset: await datasetStatus() });
}));
protectionRouter.get('/admin/false-positives', web, requireAdmin, ah(async (req, res) => {
  res.json({ items: await query("SELECT id, domain, reported_status, note, review_status, created_at FROM false_positive_reports ORDER BY created_at DESC LIMIT 200") });
}));
