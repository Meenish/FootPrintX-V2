// HTTP helpers: consistent error shape, async handler wrapper, validation.
//
// Error responses always look like:
//   { "error": { "code": "VALIDATION_FAILED", "message": "...", "details": [...] } }
// and never include stack traces, SQL, tokens or provider payloads.
import { log } from './logger.js';

export class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export const badRequest = (message, details) => new HttpError(400, 'BAD_REQUEST', message, details);
export const notFound = (what = 'Resource') => new HttpError(404, 'NOT_FOUND', `${what} not found.`);
export const forbidden = (message = 'You do not have access to this resource.', code = 'FORBIDDEN') => new HttpError(403, code, message);
export const conflict = (message, code = 'CONFLICT') => new HttpError(409, code, message);
export const unavailable = (message, code = 'SERVICE_UNAVAILABLE') => new HttpError(503, code, message);

/** Wraps an async route handler so rejections reach the error middleware. */
export const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function zodDetails(error) {
  return error.issues.slice(0, 20).map((i) => ({ path: i.path.join('.'), message: i.message }));
}

/** Validates req.body / req.query / req.params against zod schemas. */
export function validate({ body, query, params }) {
  return (req, res, next) => {
    for (const [part, schema] of [['params', params], ['query', query], ['body', body]]) {
      if (!schema) continue;
      const result = schema.safeParse(req[part] ?? {});
      if (!result.success) return next(new HttpError(400, 'VALIDATION_FAILED', 'The request is invalid.', zodDetails(result.error)));
      if (part === 'query') req.validQuery = result.data;
      else req[part] = result.data;
    }
    next();
  };
}

export function errorMiddleware(err, req, res, _next) {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) } });
  }
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large.' } });
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'Request body is not valid JSON.' } });
  log.error('unhandled request error', { requestId: req.id, route: req.route?.path, err });
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong. Please try again.' } });
}
