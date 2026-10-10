// Minimal structured logger with mandatory redaction. Every log line passes
// through redact(), so tokens, passwords, cookies, codes and email addresses
// cannot be written to logs even if a caller passes them by mistake.
import { getConfig } from './config.js';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
const SENSITIVE_KEY = /^(code|state|key|email|to)$|password|passwd|secret|token|authorization|cookie|verifier|api[-_]?key|otp|csrf|_enc$|Enc$/i;
const EMAIL_RE = /([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g;
const BEARER_RE = /(bearer\s+)[A-Za-z0-9._~+/=-]+/gi;
const LONG_SECRET_RE = /\b[A-Fa-f0-9]{40,}\b|\bya29\.[A-Za-z0-9._-]+|\b1\/\/[A-Za-z0-9._-]{20,}/g;

export function redactString(s) {
  return String(s).replace(BEARER_RE, '$1[REDACTED]').replace(LONG_SECRET_RE, '[REDACTED]').replace(EMAIL_RE, '$1***@$2');
}

export function redact(value, depth = 0) {
  if (value == null) return value;
  if (depth > 6) return '[depth]';
  if (typeof value === 'string') return redactString(value);
  if (typeof value !== 'object') return value;
  if (value instanceof Error) return { name: value.name, message: redactString(value.message), code: value.code, status: value.status ?? value.response?.status };
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) out[k] = SENSITIVE_KEY.test(k) ? '[REDACTED]' : redact(v, depth + 1);
  return out;
}

let sink = (line) => process.stdout.write(`${line}\n`);
/** Test hook to capture log output. */
export function setLogSink(fn) {
  sink = fn;
}

function emit(level, msg, fields) {
  let threshold = 'info';
  try {
    threshold = getConfig().logLevel;
  } catch {
    /* config not loaded yet */
  }
  if (LEVELS[level] < LEVELS[threshold]) return;
  const line = { t: new Date().toISOString(), level, msg: redactString(msg), ...redact(fields || {}) };
  sink(JSON.stringify(line));
}

export const log = {
  debug: (msg, f) => emit('debug', msg, f),
  info: (msg, f) => emit('info', msg, f),
  warn: (msg, f) => emit('warn', msg, f),
  error: (msg, f) => emit('error', msg, f),
};
