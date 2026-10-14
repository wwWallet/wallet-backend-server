import { pino } from 'pino';

export const logger = pino({
	level: process.env.LOG_LEVEL || 'info',

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
