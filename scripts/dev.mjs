// Runs the API (with file-watching) and the Vite dev server together.
// Usage: npm run dev   (after `npm install` and `npm run setup`)
//
// Both processes are started with the current Node binary rather than through
// `npm`/`npm.cmd`. Node >= 20.12 refuses to spawn .cmd files on Windows without
// a shell (spawn EINVAL), and going through a shell would leave child processes
// running after Ctrl+C.
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const frontendDir = path.join(root, 'frontend');
const backendDir = path.join(root, 'backend');

// Resolve Vite's CLI entry point from the frontend workspace (works whether npm hoisted it or not).
const requireFromFrontend = createRequire(path.join(frontendDir, 'package.json'));
const viteBin = path.join(path.dirname(requireFromFrontend.resolve('vite/package.json')), 'bin', 'vite.js');

const procs = [
  ['api', ['--watch', 'src/server.js'], backendDir],
  ['web', [viteBin], frontendDir],
].map(([name, args, cwd]) => {
  const p = spawn(process.execPath, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  const prefix = (d) => d.toString().split('\n').filter(Boolean).map((l) => `[${name}] ${l}`).join('\n') + '\n';
  p.stdout.on('data', (d) => process.stdout.write(prefix(d)));
  p.stderr.on('data', (d) => process.stderr.write(prefix(d)));
  p.on('error', (err) => {
    console.error(`[${name}] failed to start: ${err.message}`);
    process.exit(1);
  });
  p.on('exit', (code) => {
    console.log(`[${name}] exited with code ${code}`);
    for (const other of procs) if (other !== p) other.kill();
    process.exit(code ?? 0);
  });
  return p;
});
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => procs.forEach((p) => p.kill(sig)));
