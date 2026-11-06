import { QueryFailedError } from 'typeorm';
import { describe, expect, it } from 'vitest';
import { isStatusSlotCollision, isSupportedStatusListId, STATUS_MAX_SHARD, statusListId, utcWeekStart } from './allocator';

describe('weekly status identifiers', () => {
	it.each([
		['2026-11-08T23:59:59.999Z', '2026-11-02'],
		['2026-11-09T00:00:00Z', '2026-11-09'],
		['2027-01-01T12:00:00Z', '2026-12-28'],
		['2027-01-04T00:00:00Z', '2027-01-04'],
		['2026-11-09T01:00:00+02:00', '2026-11-02'],
		['2024-12-31T12:00:00Z', '2024-12-30'],
	])('maps %s to UTC Monday %s', (input, expected) => {
		expect(utcWeekStart(new Date(input))).toBe(expected);
	});

	it('rejects invalid dates', () => {
		expect(() => utcWeekStart(new Date(NaN))).toThrow(RangeError);
	});

	it('pins the canonical hash and separates type, week, and shard', () => {
		const id = statusListId('wa', '2026-11-02', 0);
		expect(id).toBe('-IvkJWcUf6xBjy8wBMe5E0YwbbSBOtKB7R1-wX-s3b0');
		expect(id).toHaveLength(43);
		expect(
			new Set([id, statusListId('ka', '2026-11-02', 0), statusListId('wa', '2026-11-09', 0), statusListId('wa', '2026-11-02', 1)]).size,
		).toBe(4);
		expect(isSupportedStatusListId(id)).toBe(true);
	});

	it.each([-1, 1.5, NaN, Infinity, STATUS_MAX_SHARD + 1])('rejects shard %s', (shard) => {
		expect(() => statusListId('wa', '2026-11-02', shard)).toThrow(RangeError);
	});

	it.each(['v2_' + 'a'.repeat(43), 'a'.repeat(42), 'v1_' + '!'.repeat(43), 'a'.repeat(44)])('rejects unsupported ID %s', (id) => {
		expect(isSupportedStatusListId(id)).toBe(false);
	});
});

describe('slot collision classification', () => {
	it.each(['status_slot', 'wallet_provider_status_list_entry.status_slot'])('recognizes the specific unique key %s', (key) => {
		expect(
			isStatusSlotCollision(
				new QueryFailedError(
					'INSERT',
					[],
					Object.assign(new Error(), {
						code: 'ER_DUP_ENTRY',
						sqlMessage: `Duplicate entry 'value' for key '${key}'`,
					}),
				),
			),
		).toBe(true);
	});

	it.each([
		{ code: 'ER_DUP_ENTRY', sqlMessage: "Duplicate entry 'value' for key 'PRIMARY'" },
		{ code: 'ER_LOCK_WAIT_TIMEOUT', sqlMessage: "for key 'status_slot'" },
		{ code: 'ER_DUP_ENTRY', sqlMessage: "Duplicate entry 'status_slot' for key 'other'" },
		{ code: 'ER_DUP_ENTRY' },
	])('does not mistake another failure for a slot collision: %j', (error) => {
		expect(isStatusSlotCollision(new QueryFailedError('INSERT', [], Object.assign(new Error(), error)))).toBe(false);
	});
});
