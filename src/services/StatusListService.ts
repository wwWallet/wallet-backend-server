import { deflateSync } from 'node:zlib';

export type EncodedStatusList = {
	bits: 1;
	lst: string;
};

function createInvalidStatusBytes(capacity: number): Buffer {
	// Each byte holds eight statuses. Round up to make room for every position.
	const byteCount = Math.ceil(capacity / 8);
	// 0xff is binary 11111111: all eight positions start invalid (1).
	return Buffer.alloc(byteCount, 0xff);
}

function markStatusValid(bytes: Buffer, idx: number): void {
	const byteIndex = Math.floor(idx / 8);
	const bitPosition = idx % 8;
	const bitMask = 1 << bitPosition;
	// Clear only this position to valid (0), leaving the other bits unchanged.
	bytes[byteIndex] &= ~bitMask;
}

/** Encode a one-bit list. Unlisted positions (including padding) are invalid; invalid inputs throw RangeError. */
export function encodeStatusList(capacity: number, validIndices: Iterable<number>): EncodedStatusList {
	if (!Number.isSafeInteger(capacity) || capacity <= 0) {
		throw new RangeError('Invalid status list capacity');
	}
	const bytes = createInvalidStatusBytes(capacity);
	for (const idx of validIndices) {
		if (!Number.isInteger(idx) || idx < 0 || idx >= capacity) {
			throw new RangeError('Invalid status list index');
		}
		markStatusValid(bytes, idx);
	}
	return { bits: 1, lst: deflateSync(bytes).toString('base64url') };
}
