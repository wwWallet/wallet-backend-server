type AttestationType = 'wa' | 'ka';
type Entry = { periodStart: string; shard?: number };

/** At most one week per type. Old requests cannot replace a newer week's entry. */
export class ShardCache {
	private readonly entries: Partial<Record<AttestationType, Entry>> = {};

	constructor(private readonly discover: (type: AttestationType, periodStart: string) => Promise<number>) {}

	private entry(type: AttestationType, periodStart: string): Entry {
		const current = this.entries[type];
		if (current?.periodStart === periodStart) {
			return current;
		}
		const entry: Entry = { periodStart };
		if (!current || periodStart > current.periodStart) {
			this.entries[type] = entry;
		}
		return entry;
	}

	async get(type: AttestationType, periodStart: string, refresh = false): Promise<number> {
		const entry = this.entry(type, periodStart);
		if (!refresh && entry.shard !== undefined) {
			return entry.shard;
		}
		const shard = await this.discover(type, periodStart);
		entry.shard = Math.max(entry.shard ?? 0, shard);
		return entry.shard;
	}

	/** Called only after allocation commits; concurrent completions never move backwards. */
	remember(type: AttestationType, periodStart: string, shard: number): void {
		const entry = this.entry(type, periodStart);
		entry.shard = Math.max(entry.shard ?? 0, shard);
	}
}
