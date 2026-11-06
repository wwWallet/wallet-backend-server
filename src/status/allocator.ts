import { createHash } from 'node:crypto';
import { QueryFailedError } from 'typeorm';

export const STATUS_CAPACITY = 131072;
export const STATUS_COLLISION_LIMIT = 5;
export const STATUS_INSERT_LIMIT = 50;
export const STATUS_MAX_SHARD = 4294967295;

export function utcWeekStart(now: Date): string {
	if (!Number.isFinite(now.getTime())) {
		throw new RangeError('Invalid status allocation date');
	}
	const monday = new Date(now.getTime());
	monday.setUTCHours(0, 0, 0, 0);
	monday.setUTCDate(monday.getUTCDate() - ((monday.getUTCDay() + 6) % 7));
	return monday.toISOString().slice(0, 10);
}

export function statusListId(type: 'wa' | 'ka', periodStart: string, shard: number): string {
	if (!Number.isSafeInteger(shard) || shard < 0 || shard > STATUS_MAX_SHARD) {
		throw new RangeError('Invalid status shard');
	}
	const input = JSON.stringify(['wallet-provider-status', type, periodStart, shard]);
	return createHash('sha256').update(input, 'utf8').digest('base64url');
}

export function isSupportedStatusListId(id: string): boolean {
	return /^[A-Za-z0-9_-]{43}$/.test(id);
}

/** mysql2 reports the conflicting key in sqlMessage, not in a structured field. */
export function isStatusSlotCollision(error: unknown): boolean {
	if (!(error instanceof QueryFailedError) || error.driverError.code !== 'ER_DUP_ENTRY') {
		return false;
	}
	const message = error.driverError.sqlMessage;
	return typeof message === 'string' && /\bfor key ['`](?:[^'`]+\.)?status_slot['`]\s*$/.test(message);
}
