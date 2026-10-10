// Refreshes the threat dataset from THREAT_FEEDS / THREAT_FEED_FILE.
import { bootstrap } from './_bootstrap.mjs';

const { db } = await bootstrap();
const { syncAllFeeds, datasetStatus } = await import('../src/services/reputation.js');
const results = await syncAllFeeds();
console.log(JSON.stringify({ results, dataset: await datasetStatus() }, null, 2));
await db.closeDb();
