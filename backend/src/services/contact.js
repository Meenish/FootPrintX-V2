import crypto from 'node:crypto';
import { query } from '../db.js';
import { encrypt } from '../crypto.js';
import { getConfig } from '../config.js';
import { HttpError } from '../http.js';
import { mailTransport } from './notifications.js';

export async function submitContact(userId, content) {
  const cfg = getConfig();
  const t = mailTransport();
  if (!t || !cfg.smtp.contactTo) throw new HttpError(503, 'CONTACT_UNAVAILABLE', 'Contact delivery is not configured. Your message has not been sent.');
  const id = crypto.randomUUID();
  await query('INSERT INTO contact_submissions (id,user_id,content_enc,status) VALUES ($1,$2,$3,\'pending\')', [id,userId,encrypt(JSON.stringify(content), `contact:${id}`)]);
  try {
    const result = await t.sendMail({ from: cfg.smtp.from, to: cfg.smtp.contactTo, replyTo: content.email,
      subject: `FootprintX contact ${id}`, text: `From: ${content.name}\nReply email: ${content.email}\n\n${content.message}` });
    if (!result.accepted?.length || result.rejected?.length) throw new Error('recipient_not_accepted');
  } catch {
    await query('UPDATE contact_submissions SET status=\'failed\',updated_at=now() WHERE id=$1', [id]);
    throw new HttpError(502, 'CONTACT_DELIVERY_FAILED', 'The mail service did not confirm acceptance. Please try again later.');
  }
  await query('UPDATE contact_submissions SET status=\'accepted\',updated_at=now() WHERE id=$1', [id]);
  return { id, message: 'Your message was accepted by the mail service for delivery.' };
}
