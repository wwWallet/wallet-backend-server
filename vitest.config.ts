import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		environment: 'node',
		include: ['**/*.test.ts'],
		exclude: configDefaults.exclude,
		silent: 'passed-only',
	},
});
