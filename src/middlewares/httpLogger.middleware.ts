import { pinoHttp } from 'pino-http';
import { logger } from '../logger';

export const HttpLoggerMiddleware = pinoHttp({
	logger: logger.child({ module: 'HTTP' }),

	// prevent healthcheck spam
	autoLogging: {
		ignore: (req) => req.url === '/status' || req.url?.startsWith('/status?') === true,
	},

	customLogLevel: (_req, res, err) => {
		if (err || res.statusCode >= 500) return 'error';
		if (res.statusCode >= 400) return 'warn';
		return 'info';
	},

	serializers: {
		req: (req) => ({
			method: req.method,
			url: req.url?.split('?')[0],
			query: req.query,
			headers: req.headers,
			remoteAddress: req.remoteAddress,
		}),
	},

	redact: {
		paths: ['req.headers.authorization', 'req.headers.cookie', 'req.query.*', 'res.headers["set-cookie"]'],
		censor: '[redacted]',
	},
});
