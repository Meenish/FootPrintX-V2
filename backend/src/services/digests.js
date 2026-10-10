// Optional periodic emails: weekly summary and remediation reminders. Both are
// off by default, de-duplicated per ISO week, and never sent after a routine
// scan on their own.
import { query, queryOne } from '../db.js';
import { getConfig } from '../config.js';
import { sendEmail } from './notifications.js';

function isoWeek(d = new Date()) {
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = date.getUTCDay() || 7;
  date.setUTCDate(date.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1));
  return `${date.getUTCFullYear()}-W${String(Math.ceil(((date - yearStart) / 864e5 + 1) / 7)).padStart(2, '0')}`;
}

export async function sendDigests() {
  const week = isoWeek();
  const app = getConfig().appUrl;
  const summaryUsers = await query('SELECT user_id FROM notification_preferences WHERE periodic_summary_email');
  for (const { user_id: userId } of summaryUsers) {
    const snap = await queryOne('SELECT score, level, confidence, delta FROM dasi_snapshots WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1', [userId]);
    const open = await queryOne("SELECT count(*)::int AS n FROM recommendations WHERE user_id = $1 AND applicable AND status IN ('recommended','in_progress')", [userId]);
    const alerts = await queryOne("SELECT count(*)::int AS n FROM alerts WHERE user_id = $1 AND created_at > now() - interval '7 days'", [userId]);
    await sendEmail(userId, {
      category: 'periodic_summary',
      dedupKey: `summary:${week}`,
      subject: '[FootprintX] Your weekly security summary',
      text: [
        snap?.score != null ? `DASI: ${snap.score}/100 (${snap.level}, confidence ${snap.confidence}).` : 'DASI: not yet assessed.',
        `Open recommendations: ${open.n}.`,
        `New alerts this week: ${alerts.n}.`,
        `Review: ${app}/dashboard`,
      ].join('\n'),
    });
  }
  const reminderUsers = await query('SELECT user_id FROM notification_preferences WHERE remediation_reminders_email');
  for (const { user_id: userId } of reminderUsers) {
    const stale = await query(
      "SELECT title FROM recommendations WHERE user_id = $1 AND applicable AND status = 'in_progress' AND status_changed_at < now() - interval '7 days' ORDER BY priority DESC LIMIT 5",
      [userId]
    );
    if (!stale.length) continue;
    await sendEmail(userId, {
      category: 'remediation_reminders',
      dedupKey: `reminder:${week}`,
      subject: '[FootprintX] Security steps you started',
      text: `You marked these as in progress more than a week ago:\n${stale.map((s) => `• ${s.title}`).join('\n')}\n\nMark them done or update them: ${app}/recommendations`,
    });
  }
}
