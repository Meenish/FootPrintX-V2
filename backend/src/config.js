// Environment configuration. Validated once at startup; the process refuses to
// start with an unsafe or incomplete configuration instead of silently
// falling back to insecure defaults (no hard-coded keys, no demo logins).
import { z } from 'zod';

const bool = (def) =>
  z
    .enum(['true', 'false', '1', '0', ''])
    .optional()
    .transform((v) => (v === undefined || v === '' ? def : v === 'true' || v === '1'));
const int = (def, min, max) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? def : Number(v)))
    .pipe(z.number().int().min(min).max(max));
const optStr = z
  .string()
  .optional()
  .transform((v) => (v ? v.trim() : undefined));

const HEX64 = /^[0-9a-f]{64}$/i;

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: int(5000, 1, 65535),
  HOST: z.string().default('127.0.0.1'),
  APP_URL: z.string().url().default('http://localhost:5173'),
  API_PUBLIC_URL: z.string().url().default('http://localhost:5000'),
  DATABASE_URL: z.string().default('pglite:./data/pglite'),
  ENCRYPTION_KEYS: optStr,
  ENCRYPTION_KEY: optStr, // legacy single-key form, treated as key id "k1"
  INDEX_KEY: optStr,
  TRUST_PROXY: int(0, 0, 10),
  CORS_ORIGINS: optStr,
  EXTENSION_ORIGINS: optStr,
  SERVE_FRONTEND: bool(false),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error', 'silent']).default('info'),
  RUN_WORKER: bool(true),
  RUN_SCHEDULER: bool(true),

  GOOGLE_CLIENT_ID: optStr,
  GOOGLE_CLIENT_SECRET: optStr,
  GOOGLE_REDIRECT_URI: optStr,
  GMAIL_SCOPE_MODE: z.enum(['metadata', 'readonly']).default('metadata'),
  SCAN_MAX_MESSAGES: int(1500, 50, 20000),
  MONITOR_INTERVAL_HOURS: int(24, 0, 24 * 30),
  DEV_SYNTHETIC_DATA: bool(false),

  BREACH_PROVIDER: z.enum(['none', 'xposedornot', 'hibp']).default('none'),
  HIBP_API_KEY: optStr,
  BREACH_INCLUDE_SENSITIVE: bool(false),
  BREACH_RECHECK_MIN_HOURS: int(24, 0, 24 * 30),

  THREAT_FEEDS: optStr,
  THREAT_FEED_FILE: optStr,
  THREAT_SYNC_INTERVAL_HOURS: int(12, 0, 24 * 7),
  THREAT_DATASET_MAX_AGE_HOURS: int(72, 1, 24 * 30),
  THREAT_FEED_MAX_ENTRIES: int(500000, 10, 5000000),

  BILLING_MODE: z.enum(['disabled', 'development']).default('disabled'),
  PREMIUM_PRICE_MINOR: int(14900, 0, 100000000),
  PREMIUM_CURRENCY: z.string().regex(/^[A-Z]{3}$/).default('INR'),
  PREMIUM_PRICE_STATUS: z.enum(['proposed', 'final']).default('proposed'),
  PREMIUM_INTERVAL: z.enum(['month', 'year']).default('month'),
  DEV_PREMIUM_DAYS: int(30, 1, 366),

  CONTACT_TO: z.preprocess((v) => v === '' ? undefined : v, z.string().email().optional()),
  SMTP_HOST: optStr,
  SMTP_PORT: int(587, 1, 65535),
  SMTP_SECURE: bool(false),
  SMTP_USER: optStr,
  SMTP_PASSWORD: optStr,
  SMTP_FROM: optStr,
  SECURITY_EMAILS_PER_DAY: int(5, 1, 100),
});

function parseKeyRing(env) {
  const raw = env.ENCRYPTION_KEYS || (env.ENCRYPTION_KEY ? `k1:${env.ENCRYPTION_KEY}` : '');
  if (!raw) return { keys: [], problems: ['ENCRYPTION_KEYS is required (format "k1:<64 hex chars>"; run `npm run setup` to generate one).'] };
  const keys = [];
  const problems = [];
  for (const part of raw.split(',').map((p) => p.trim()).filter(Boolean)) {
    const [id, hex] = part.includes(':') ? part.split(':') : ['k1', part];
    if (!/^[a-zA-Z0-9_-]{1,16}$/.test(id)) problems.push(`Encryption key id "${id}" is invalid.`);
    else if (!HEX64.test(hex || '')) problems.push(`Encryption key "${id}" must be 64 hex characters (32 bytes).`);
    else if (/^(.)\1+$/.test(hex)) problems.push(`Encryption key "${id}" is a trivially guessable value.`);
    else keys.push({ id, key: Buffer.from(hex, 'hex') });
  }
  if (new Set(keys.map((k) => k.id)).size !== keys.length) problems.push('Encryption key ids must be unique.');
  return { keys, problems };
}

export function loadConfig(env = process.env) {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`);
    throw new Error(`Invalid environment configuration:\n${lines.join('\n')}`);
  }
  const e = parsed.data;
  const problems = [];
  const isProd = e.NODE_ENV === 'production';

  const ring = parseKeyRing(env);
  problems.push(...ring.problems);
  if (!e.INDEX_KEY || !HEX64.test(e.INDEX_KEY)) problems.push('INDEX_KEY is required: 64 hex characters, used for keyed hashes (run `npm run setup`).');
  else if (/^(.)\1+$/.test(e.INDEX_KEY) && isProd) problems.push('INDEX_KEY is a trivially guessable value.');
  if (ring.keys.length && e.INDEX_KEY && ring.keys.some((k) => k.key.toString('hex') === e.INDEX_KEY.toLowerCase())) {
    problems.push('INDEX_KEY must differ from every encryption key.');
  }

  const isPglite = e.DATABASE_URL.startsWith('pglite:');
  if (!isPglite && !/^postgres(ql)?:\/\//.test(e.DATABASE_URL)) problems.push('DATABASE_URL must be a postgres:// URL or pglite:<dir|memory>.');

  const googleConfigured = !!(e.GOOGLE_CLIENT_ID && e.GOOGLE_CLIENT_SECRET);
  if ((e.GOOGLE_CLIENT_ID || e.GOOGLE_CLIENT_SECRET) && !googleConfigured) problems.push('Set both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, or neither.');
  if (e.BREACH_PROVIDER === 'hibp' && !e.HIBP_API_KEY) problems.push('BREACH_PROVIDER=hibp requires HIBP_API_KEY.');

  const smtpConfigured = !!(e.SMTP_HOST && e.SMTP_FROM);

  if (isProd) {
    if (isPglite) problems.push('Production requires a PostgreSQL DATABASE_URL; PGlite is for local development and tests only.');
    if (e.DEV_SYNTHETIC_DATA) problems.push('DEV_SYNTHETIC_DATA must be false in production.');
    if (e.BILLING_MODE === 'development') problems.push('BILLING_MODE=development grants Premium without payment and is not allowed in production.');
    if (!e.APP_URL.startsWith('https://')) problems.push('APP_URL must use https:// in production.');
    if (!e.API_PUBLIC_URL.startsWith('https://')) problems.push('API_PUBLIC_URL must use https:// in production.');
  }

  if (problems.length) throw new Error(`Invalid environment configuration:\n${problems.map((p) => `  - ${p}`).join('\n')}`);

  const appOrigin = new URL(e.APP_URL).origin;
  const list = (v) => (v ? v.split(',').map((s) => s.trim()).filter(Boolean) : []);
  // A server with no threat dataset can only answer "unknown" for every website
  // check and every extension lookup, which reads as a broken product rather
  // than a safe default. Outside production (and outside tests, which must stay
  // hermetic) fall back to the public feed when the operator set nothing, so a
  // fresh checkout and an existing .env written before this default both work.
  // Set THREAT_FEEDS=none to opt out.
  const feedsRaw = list(e.THREAT_FEEDS);
  const feedsOptOut = feedsRaw.length === 1 && feedsRaw[0] === 'none';
  const feeds = feedsOptOut
    ? []
    : feedsRaw.length || isProd || e.NODE_ENV === 'test' || e.THREAT_FEED_FILE
      ? feedsRaw
      : ['phishing_database'];

  return Object.freeze({
    env: e.NODE_ENV,
    isProduction: isProd,
    isTest: e.NODE_ENV === 'test',
    port: e.PORT,
    host: e.HOST,
    appUrl: e.APP_URL.replace(/\/$/, ''),
    appOrigin,
    apiPublicUrl: e.API_PUBLIC_URL.replace(/\/$/, ''),
    databaseUrl: e.DATABASE_URL,
    usesPglite: isPglite,
    keyRing: ring.keys,
    indexKey: Buffer.from(e.INDEX_KEY, 'hex'),
    trustProxy: e.TRUST_PROXY,
    corsOrigins: [appOrigin, ...list(e.CORS_ORIGINS)],
    extensionOrigins: list(e.EXTENSION_ORIGINS),
    serveFrontend: e.SERVE_FRONTEND,
    logLevel: e.LOG_LEVEL,
    runWorker: e.RUN_WORKER,
    runScheduler: e.RUN_SCHEDULER,
    cookieSecure: isProd || e.APP_URL.startsWith('https://'),
    google: {
      configured: googleConfigured,
      clientId: e.GOOGLE_CLIENT_ID,
      clientSecret: e.GOOGLE_CLIENT_SECRET,
      redirectUri: e.GOOGLE_REDIRECT_URI || `${e.API_PUBLIC_URL.replace(/\/$/, '')}/api/connections/google/callback`,
      scopeMode: e.GMAIL_SCOPE_MODE,
    },
    scan: { maxMessages: e.SCAN_MAX_MESSAGES, monitorIntervalHours: e.MONITOR_INTERVAL_HOURS },
    syntheticData: e.DEV_SYNTHETIC_DATA,
    breach: {
      provider: e.BREACH_PROVIDER,
      hibpApiKey: e.HIBP_API_KEY,
      includeSensitive: e.BREACH_INCLUDE_SENSITIVE,
      recheckMinHours: e.BREACH_RECHECK_MIN_HOURS,
    },
    threat: {
      feeds,
      feedFile: e.THREAT_FEED_FILE,
      syncIntervalHours: e.THREAT_SYNC_INTERVAL_HOURS,
      maxDatasetAgeHours: e.THREAT_DATASET_MAX_AGE_HOURS,
      maxEntries: e.THREAT_FEED_MAX_ENTRIES,
    },
    billing: {
      mode: e.BILLING_MODE,
      priceMinor: e.PREMIUM_PRICE_MINOR,
      currency: e.PREMIUM_CURRENCY,
      priceStatus: e.PREMIUM_PRICE_STATUS,
      interval: e.PREMIUM_INTERVAL,
      devPremiumDays: e.DEV_PREMIUM_DAYS,
    },
    smtp: {
      configured: smtpConfigured,
      contactTo: e.CONTACT_TO,
      host: e.SMTP_HOST,
      port: e.SMTP_PORT,
      secure: e.SMTP_SECURE || e.SMTP_PORT === 465,
      user: e.SMTP_USER,
      password: e.SMTP_PASSWORD,
      from: e.SMTP_FROM,
      securityEmailsPerDay: e.SECURITY_EMAILS_PER_DAY,
    },
  });
}

let current;
export function getConfig() {
  if (!current) current = loadConfig();
  return current;
}
/** Test hook: replace the active configuration. */
export function setConfig(cfg) {
  current = cfg;
}
