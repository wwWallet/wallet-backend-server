import { pino } from 'pino';

const CENSOR = '[redacted]';

const redactPaths = [
	'body.password',
	'body.privateData',
	'body.keys',
	'body.credential.clientExtensionResults',
	'user.passwordHash',
	'user.privateData',
	'user.keys',
	'userRes.passwordHash',
	'userRes.privateData',
	'userRes.keys',
	'userRes.val.passwordHash',
	'userRes.val.privateData',
	'userRes.val.keys',
	'challenge.prfSalt',
	'verifier',
];

export const logger = pino({
	level: process.env.LOG_LEVEL || 'info',

	redact: {
		paths: redactPaths,
		censor: CENSOR,
	},

	transport: process.env.NODE_ENV !== 'production' ?
		{
			target: 'pino-pretty',
			options: {
				colorize: true,
				messageFormat: '{if module}[{module}] {end}{msg}',
				ignore: 'pid,hostname,module',
			},
		} : undefined,
});
