// Grants the admin role to an existing user. Usage: npm run make-admin -- user@example.com
import { bootstrap } from './_bootstrap.mjs';

const email = (process.argv[2] || '').trim().toLowerCase();
if (!email) {
  console.error('Usage: node scripts/make-admin.mjs <email>');
  process.exit(1);
}
const { db } = await bootstrap();
const rows = await db.query("UPDATE users SET role = 'admin' WHERE email = $1 RETURNING id", [email]);
console.log(rows.length ? `${email} is now an admin.` : `No user with email ${email}.`);
await db.closeDb();
