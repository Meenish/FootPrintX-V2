// Standalone background worker (set RUN_WORKER=false / RUN_SCHEDULER=false on
// API instances when running this separately).
import './env.js';
import { loadConfig, setConfig } from './config.js';
import { log } from './logger.js';

try {
  setConfig(loadConfig());
} catch (err) {
  console.error(err.message);
  process.exit(1);
}
const { initDb, migrate } = await import('./db.js');
const { startWorker, startScheduler } = await import('./services/worker.js');
await initDb();
await migrate();
startWorker();
startScheduler();
log.info('FootprintX worker running');
setInterval(() => {}, 1 << 30);
