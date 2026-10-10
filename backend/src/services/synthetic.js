// SYNTHETIC DEVELOPMENT MAILBOX. Enabled only when DEV_SYNTHETIC_DATA=true
// (rejected in production configuration). It feeds clearly labelled fixture
// messages through the *real* discovery pipeline so the product can be
// demonstrated and tested without Google credentials. Every record created
// from it carries is_synthetic=true and the UI shows a "Synthetic data" label.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { query } from '../db.js';
import { getConfig } from '../config.js';
import { HttpError } from '../http.js';

const FIXTURE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../fixtures/synthetic-mailbox.json');
let cached;
export function syntheticFixture() {
  if (!cached) cached = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  return cached;
}

export function assertSyntheticEnabled() {
  if (!getConfig().syntheticData) throw new HttpError(404, 'NOT_FOUND', 'Synthetic development data is not enabled on this server.');
}

const DAY = 864e5;

export async function* iterateSynthetic({ connection, now = Date.now() }) {
  const fixture = syntheticFixture();
  const messages = fixture.messages.map((m) => ({
    id: m.id,
    from: m.from,
    subject: m.subject,
    snippet: '',
    authResults: m.auth,
    internalDate: now - m.daysAgo * DAY,
  }));
  const injected = await query('SELECT id, from_header, subject, auth_results, internal_date FROM synthetic_messages WHERE connection_id = $1 ORDER BY internal_date', [connection.id]);
  for (const r of injected) messages.push({ id: `inj-${r.id}`, from: r.from_header, subject: r.subject, snippet: '', authResults: r.auth_results, internalDate: new Date(r.internal_date).getTime() });
  const outcome = { source: 'synthetic_mailbox', status: 'ok', listed: messages.length, fetched: 0, failed: 0 };
  for (let i = 0; i < messages.length; i += 8) {
    const batch = messages.slice(i, i + 8);
    outcome.fetched += batch.length;
    yield { source: 'synthetic_mailbox', messages: batch, outcome: { ...outcome, inProgress: i + 8 < messages.length } };
  }
  yield { source: 'synthetic_mailbox', messages: [], outcome };
}

// Templates for injecting a security notification into a synthetic mailbox,
// e.g. to demonstrate independent verification of a reported password change.
const TEMPLATES = {
  password_changed: (name) => `Your ${name} password was changed`,
  mfa_enabled: () => 'Two-step verification is now turned on',
  security_alert: () => 'Security alert: unusual sign-in to your account',
  signup: (name) => `Welcome to ${name}`,
};

export async function injectSyntheticMessage(userId, connection, { kind, domain, serviceName }) {
  assertSyntheticEnabled();
  if (!connection.is_synthetic) throw new HttpError(400, 'NOT_SYNTHETIC', 'Messages can only be injected into a synthetic mailbox.');
  const name = serviceName || domain;
  await query(
    'INSERT INTO synthetic_messages (user_id, connection_id, from_header, subject, auth_results) VALUES ($1, $2, $3, $4, $5)',
    [userId, connection.id, `${name} <no-reply@${domain}>`, TEMPLATES[kind](name), `dmarc=pass header.from=${domain}`]
  );
}

/** Synthetic breach provider: only ever used for synthetic connections. */
export const syntheticBreachProvider = {
  name: 'synthetic',
  label: 'Synthetic breach fixture (development only)',
  async checkEmail() {
    return { breaches: syntheticFixture().breaches };
  },
};
