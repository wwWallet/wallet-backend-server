import eslint from '@eslint/js';
import vitest from '@vitest/eslint-plugin';
import { defineConfig } from 'eslint/config';
import prettierConfig from 'eslint-config-prettier/flat';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig(
	{
		ignores: ['dist/**', 'node_modules/**'],
	},
	{
		files: ['src/**/*.ts', 'config/**/*.ts'],
		extends: [eslint.configs.recommended, tseslint.configs.recommended],
		linterOptions: {
			reportUnusedDisableDirectives: 'error',
		},
		languageOptions: {
			globals: globals.node,
		},
		rules: {
			'@typescript-eslint/no-explicit-any': 'off',
			'@typescript-eslint/no-empty-object-type': 'off',
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
				},
			],
		},
	},
	{
		...vitest.configs.recommended,
		files: ['{src,config}/**/*.test.ts'],
	},
	prettierConfig,
	{
		rules: {
			'no-unexpected-multiline': 'error',
		},
	},
);
