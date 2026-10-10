// Express application assembly. No listening or background work here, so the
// app can be created in tests against an in-memory database.
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { getConfig } from './config.js';
import { log } from './logger.js';
import { ping, pendingMigrations } from './db.js';
import { errorMiddleware, HttpError, ah } from './http.js';
import { requestId, authenticate, requireJsonForUnsafe, limits } from './middleware.js';
import { authRouter } from './routes/auth.js';
import { coreRouter } from './routes/core.js';
import { protectionRouter } from './routes/protection.js';
import { settingsRouter } from './routes/settings.js';
import { planCatalog } from './services/billing.js';
import { configuredProvider } from './services/breach.js';
import { MODEL_VERSION } from './services/dasi.js';

export const APP_VERSION = '2.0.0';
const FRONTEND_DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../frontend/dist');

function corsMiddleware(cfg) {
  const webOrigins = new Set(cfg.corsOrigins);
  const extOrigins = new Set(cfg.extensionOrigins);
  const ownOrigin = new URL(cfg.apiPublicUrl).origin;
  return (req, res, next) => {
    const origin = req.headers.origin;
    if (!origin) return next();
    res.vary('Origin');
    if (webOrigins.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    } else if (extOrigins.has(origin)) {
      // Extensions authenticate with a Bearer token; never with cookies.
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else if (origin !== ownOrigin && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !/^(chrome|moz|safari-web)-extension:\/\//.test(origin)) {
      // Defence in depth against cross-site requests riding on cookies.
      return next(new HttpError(403, 'ORIGIN_NOT_ALLOWED', 'This origin is not allowed.'));
    }
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token, Authorization');
      res.setHeader('Access-Control-Max-Age', '600');
      return res.status(204).end();
    }
    next();
  };
}

function requestLogger(req, res, next) {
  const started = process.hrtime.bigint();
  res.on('finish', () => {
    // Route patterns only: no ids, query strings, tokens or bodies in logs.
    const route = req.route ? `${req.baseUrl}${req.route.path}` : req.baseUrl || 'unmatched';
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'info' : 'debug';
    log[level]('request', { requestId: req.id, method: req.method, route, status: res.statusCode, ms: Math.round(ms) });
  });
  next();
}

export function createApp() {
  const cfg = getConfig();
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', cfg.trustProxy);
  app.use(requestId);
  app.use(requestLogger);
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"],
          'img-src': ["'self'", 'data:'],
          'font-src': ["'self'"],
          'connect-src': ["'self'"],
          'object-src': ["'none'"],
          'base-uri': ["'self'"],
          'form-action': ["'self'"],
          'frame-ancestors': ["'none'"],
          ...(cfg.isProduction ? { 'upgrade-insecure-requests': [] } : {}),
        },
      },
      strictTransportSecurity: cfg.isProduction ? { maxAge: 31536000, includeSubDomains: true } : false,
      referrerPolicy: { policy: 'no-referrer' },
    })
  );
  app.use('/api', corsMiddleware(cfg));
  app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use('/api', express.json({ limit: '64kb' }));
  app.use('/api', cookieParser());
  app.use('/api', limits.global, requireJsonForUnsafe, authenticate);

  app.get('/api/health', (req, res) => res.json({ status: 'ok', version: APP_VERSION }));
  app.get('/api/ready', ah(async (req, res) => {
    try {
      await ping();
      const pending = await pendingMigrations();
      if (pending.length) return res.status(503).json({ ready: false, reason: 'migrations_pending' });
      res.json({ ready: true });
    } catch {
      res.status(503).json({ ready: false, reason: 'database_unavailable' });
    }
  }));
  app.get('/api/config', (req, res) => {
    res.json({
      version: APP_VERSION,
      dasiModelVersion: MODEL_VERSION,
      googleConfigured: cfg.google.configured,
      gmailScopeMode: cfg.google.scopeMode,
      syntheticDataEnabled: cfg.syntheticData,
      breachProvider: configuredProvider(),
      billing: planCatalog(),
      emailDeliveryConfigured: cfg.smtp.configured,
      contactConfigured: cfg.smtp.configured && !!cfg.smtp.contactTo,
      environment: cfg.env,
    });
  });

  app.use('/api/auth', authRouter);
  app.use('/api', coreRouter);
  app.use('/api', protectionRouter);
  app.use('/api', settingsRouter);
  app.use('/api', (req, res, next) => next(new HttpError(404, 'NOT_FOUND', 'Unknown API endpoint.')));

  if (cfg.serveFrontend && fs.existsSync(FRONTEND_DIST)) {
    app.use(express.static(FRONTEND_DIST, { index: false, maxAge: '1h' }));
    app.get('*', (req, res) => res.sendFile(path.join(FRONTEND_DIST, 'index.html')));
  }
  app.use(errorMiddleware);
  return app;
}
