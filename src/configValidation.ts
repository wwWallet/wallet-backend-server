const unsafeEnvPrefixes = [
	'DEBUG_',
	'DEV_',
	'UNSAFE_',
	'INSECURE_',
];

export function getUnsafeEnvironmentVariables(): string[] {
	return Object.entries(process.env)
		.filter(([key]) =>
			unsafeEnvPrefixes.some(prefix =>
				key.startsWith(prefix)
			)
		)
		.map(([key]) => key);
}
