// Background job runner and periodic task scheduler. Runs inside the API
// process by default (RUN_WORKER / RUN_SCHEDULER) or as a separate process via
// `npm run worker`. Coordination happens through PostgreSQL (SKIP LOCKED for
// jobs, lease rows for periodic tasks), so several processes can run safely.
import { query, queryOne } from '../db.js';
import { getConfig } from '../config.js';
import { log } from '../logger.js';
import { claimNextJob, runJob, recoverStaleJobs, enqueueDueMonitoringScans } from './scanner.js';
import { syncAllFeeds } from './reputation.js';
import { runMaintenance } from './maintenance.js';
import { sendDigests } from './digests.js';

let timer = null;
let running = 0;
const MAX_CONCURRENCY = 2;

async function tick() {
  while (running < MAX_CONCURRENCY) {
    let job;
    try {
      job = await claimNextJob();
    } catch (err) {
      log.error('job claim failed', { err });
      return;
    }
    if (!job) return;
    running += 1;
    runJob(job)
      .catch((err) => log.error('job crashed', { jobId: job.id, err }))
      .finally(() => {
        running -= 1;
      });
  }
}

export function startWorker(intervalMs = 1500) {
  if (timer) return;
  timer = setInterval(() => tick().catch(() => {}), intervalMs);
  timer.unref?.();
  log.info('scan worker started');
}

export function stopWorker() {
  if (timer) clearInterval(timer);
  timer = null;
}

/** Test/CLI helper: run queued jobs until none remain (sequentially). */
export async function drainJobs(max = 50) {
  for (let i = 0; i < max; i += 1) {
    const job = await claimNextJob();
    if (!job) return i;
    await runJob(job);
  }
  return max;
}

// ---- Periodic tasks -------------------------------------------------------------

/** Runs `fn` if this process wins the lease for `name` and it is due. */
export async function runIfDue(name, everyMs, fn) {
  const lease = await queryOne(
    `INSERT INTO scheduled_tasks (name, last_started_at, locked_until) VALUES ($1, now(), now() + interval '30 minutes')
     ON CONFLICT (name) DO UPDATE SET last_started_at = now(), locked_until = now() + interval '30 minutes'
       WHERE (scheduled_tasks.locked_until IS NULL OR scheduled_tasks.locked_until < now())
         AND (scheduled_tasks.last_finished_at IS NULL OR scheduled_tasks.last_finished_at < now() - make_interval(secs => $2))
     RETURNING name`,
    [name, Math.floor(everyMs / 1000)]
  );
  if (!lease) return false;
  let status = 'ok';
  try {
    await fn();
  } catch (err) {
    status = 'failed';
    log.error('scheduled task failed', { task: name, err });
  }
  await query('UPDATE scheduled_tasks SET last_finished_at = now(), last_status = $2, locked_until = NULL WHERE name = $1', [name, status]);
  return true;
}

let schedTimer = null;
export function startScheduler(intervalMs = 60e3) {
  if (schedTimer) return;
  const cfg = getConfig();
  const loop = async () => {
    await recoverStaleJobs().catch((err) => log.error('stale job recovery failed', { err }));
    if (cfg.scan.monitorIntervalHours) await runIfDue('monitor_scans', 60 * 60e3, enqueueDueMonitoringScans);
    if (cfg.threat.syncIntervalHours && (cfg.threat.feeds.length || cfg.threat.feedFile)) await runIfDue('threat_sync', cfg.threat.syncIntervalHours * 3600e3, syncAllFeeds);
    await runIfDue('maintenance', 60 * 60e3, runMaintenance);
    await runIfDue('digests', 24 * 3600e3, sendDigests);
  };
  schedTimer = setInterval(() => loop().catch(() => {}), intervalMs);
  schedTimer.unref?.();
  setTimeout(() => loop().catch(() => {}), 2000).unref?.();
  log.info('scheduler started');
}

export function stopScheduler() {
  if (schedTimer) clearInterval(schedTimer);
  schedTimer = null;
}
