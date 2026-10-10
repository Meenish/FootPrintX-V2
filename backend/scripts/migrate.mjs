// Applies pending SQL migrations (idempotent). Usage: npm run migrate
import { bootstrap } from './_bootstrap.mjs';

const { db } = await bootstrap({ migrate: false });
const ran = await db.migrate();
console.log(ran.length ? `Applied migrations: ${ran.join(', ')}` : 'Database is up to date.');
await db.closeDb();
