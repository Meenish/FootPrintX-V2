// Local security-event log and opt-in synchronisation.
//
// Only warnings are recorded (known-threat blocks, suspicious-site warnings,
// cached results that became threats). Routine clean visits are never
// recorded here and never sent. Events are uploaded only when the user has
// turned on sync (which the server also enforces per extension session).
import { EXTENSION_EVENT_TYPES } from '@footprintx/shared/threat';

const MAX_LOCAL = 100;
const MAX_QUEUE = 50;

export function createEventLog({ local, api, now = Date.now, uuid = () => crypto.randomUUID() }) {
  async function record({ type, hostname, status, reasonCodes = [], datasetVersion = null }, { sync }) {
    if (!EXTENSION_EVENT_TYPES.includes(type)) throw new Error(`Unknown event type ${type}`);
    const event = { clientEventId: uuid(), type, domain: hostname, status, reasonCodes: reasonCodes.filter((c) => /^[A-Z_]{2,40}$/.test(c)).slice(0, 10), occurredAt: new Date(now()).toISOString() };
    if (datasetVersion) event.datasetVersion = String(datasetVersion).slice(0, 60);
    const log = (await local.get('fx_events')) || [];
    log.unshift({ ...event, synced: false });
    await local.set('fx_events', log.slice(0, MAX_LOCAL));
    if (sync) {
      const queue = (await local.get('fx_event_queue')) || [];
      queue.push(event);
      await local.set('fx_event_queue', queue.slice(-MAX_QUEUE));
    }
    return event;
  }

  /** Uploads queued events. Returns { sent, kept }. Safe to call repeatedly. */
  async function flush({ syncEnabled }) {
    const queue = (await local.get('fx_event_queue')) || [];
    if (!queue.length) return { sent: 0, kept: 0 };
    if (!syncEnabled) {
      await local.set('fx_event_queue', []);
      return { sent: 0, kept: 0, dropped: queue.length };
    }
    const batch = queue.slice(0, 20);
    const res = await api.sendEvents(batch);
    if (!res.ok) {
      // Auth/entitlement/validation problems: drop (they will not succeed on retry).
      if (res.status >= 400 && res.status < 500 && res.status !== 429) {
        await local.set('fx_event_queue', queue.slice(batch.length));
        return { sent: 0, kept: queue.length - batch.length, dropped: batch.length };
      }
      return { sent: 0, kept: queue.length };
    }
    const sentIds = new Set(batch.map((e) => e.clientEventId));
    await local.set('fx_event_queue', queue.slice(batch.length));
    const log = (await local.get('fx_events')) || [];
    await local.set('fx_events', log.map((e) => (sentIds.has(e.clientEventId) ? { ...e, synced: true } : e)));
    return { sent: batch.length, kept: queue.length - batch.length };
  }

  return { record, flush, list: async () => (await local.get('fx_events')) || [], clear: async () => { await local.set('fx_events', []); await local.set('fx_event_queue', []); } };
}
