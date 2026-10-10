// DEVELOPMENT ONLY. Creates a test user with a freshly generated random
// password (printed once) and connects the labelled synthetic mailbox.
// Refuses to run in production or when DEV_SYNTHETIC_DATA is off.
import crypto from 'node:crypto';
import { bootstrap } from './_bootstrap.mjs';

const { cfg, db } = await bootstrap();
if (cfg.isProduction || !cfg.syntheticData) {
  console.error('seed:dev only runs with NODE_ENV!=production and DEV_SYNTHETIC_DATA=true.');
  process.exit(1);
}
const { registerUser } = await import('../src/services/auth.js');
const { connectSynthetic } = await import('../src/services/connections.js');
const { enqueueScan } = await import('../src/services/scanner.js');
const { drainJobs } = await import('../src/services/worker.js');
const email = `dev-${crypto.randomBytes(3).toString('hex')}@footprintx.invalid`;
const password = crypto.randomBytes(12).toString('base64url');
const user = await registerUser({ email, password, displayName: 'Synthetic Dev User' });
const { connectionId } = await connectSynthetic(user.id);
await enqueueScan(user.id, connectionId, 'onboarding');
await drainJobs();
console.log('Synthetic development user created (data is SYNTHETIC):');
console.log(`  email:    ${email}`);
console.log(`  password: ${password}   (shown once; not stored anywhere in plain text)`);
await db.closeDb();
