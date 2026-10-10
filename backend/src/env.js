// Loads backend/.env (or the repository-root .env) before configuration is read.
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const here = path.dirname(fileURLToPath(import.meta.url));
for (const candidate of [path.resolve(here, '../.env'), path.resolve(here, '../../.env')]) {
  if (fs.existsSync(candidate)) {
    dotenv.config({ path: candidate, quiet: true });
    break;
  }
}
