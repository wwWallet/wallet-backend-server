const truthyEnvValues = new Set([
	'true',
	'1',
	'yes',
	'on',
]);

const unsafeEnvPrefixes = [
	'DEBUG_',
	'DEV_',
	'UNSAFE_',
	'INSECURE_',
];

const isTruthy = (value?: string): boolean =>
	truthyEnvValues.has(
		value?.trim().toLowerCase() ?? ''
	);

export function getEnabledUnsafeEnvironmentVariables(): string[] {
	return Object.entries(process.env)
		.filter(([key]) =>
			unsafeEnvPrefixes.some(prefix =>
				key.startsWith(prefix)
			)
		)
		.filter(([, value]) => isTruthy(value))
		.map(([key]) => key);
}
