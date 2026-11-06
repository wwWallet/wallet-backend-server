import { describe, expect, it, vi } from 'vitest';
import { ShardCache } from './ShardCache';

describe('ShardCache', () => {
	const week = '2026-11-02';

	it('allows concurrent discovery without moving backwards and reuses the cached result', async () => {
		const resolvers: Array<(value: number) => void> = [];
		const discover = vi.fn(
			() =>
				new Promise<number>((done) => {
					resolvers.push(done);
				}),
		);
		const cache = new ShardCache(discover);
		const first = cache.get('wa', week);
		const second = cache.get('wa', week);
		expect(discover).toHaveBeenCalledTimes(2);
		resolvers[1](7);
		expect(await second).toBe(7);
		resolvers[0](3);
		expect(await first).toBe(7);
		expect(await cache.get('wa', week)).toBe(7);
		expect(discover).toHaveBeenCalledTimes(2);
	});

	it('retries discovery after a failure', async () => {
		const discover = vi.fn().mockRejectedValueOnce(new Error('unavailable')).mockResolvedValue(2);
		const cache = new ShardCache(discover);
		await expect(cache.get('wa', week)).rejects.toThrow('unavailable');
		expect(await cache.get('wa', week)).toBe(2);
		expect(discover).toHaveBeenCalledTimes(2);
	});

	it('keeps types independent and replaces the week without retaining old entries', async () => {
		const discover = vi.fn().mockResolvedValue(0);
		const cache = new ShardCache(discover);
		cache.remember('wa', week, 8);
		cache.remember('ka', week, 3);
		expect(await cache.get('wa', week)).toBe(8);
		expect(await cache.get('ka', week)).toBe(3);
		const nextWeek = '2026-11-09';
		expect(await cache.get('wa', nextWeek)).toBe(0);
		cache.remember('wa', week, 99);
		expect(await cache.get('wa', nextWeek)).toBe(0);
		await cache.get('wa', week);
		await cache.get('wa', week);
		// Old requests do not reinsert an evicted week.
		expect(discover).toHaveBeenCalledTimes(3);
	});

	it('never moves backwards when discovery and committed allocations complete out of order', async () => {
		let resolve!: (value: number) => void;
		const cache = new ShardCache(
			() =>
				new Promise<number>((done) => {
					resolve = done;
				}),
		);
		cache.remember('wa', week, 4);
		const refresh = cache.get('wa', week, true);
		cache.remember('wa', week, 8);
		cache.remember('wa', week, 6);
		resolve(5);
		expect(await refresh).toBe(8);
		expect(await cache.get('wa', week)).toBe(8);
	});
});
