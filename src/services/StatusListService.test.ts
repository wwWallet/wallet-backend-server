import { inflateSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { encodeStatusList } from './StatusListService';

describe('one-bit status list encoding', () => {
	it('starts all positions invalid', () => {
		const result = encodeStatusList(131072, []);
		expect(result.bits).toBe(1);
		expect(inflateSync(Buffer.from(result.lst, 'base64url'))).toEqual(Buffer.alloc(16384, 0xff));
	});

	it('encodes valid positions least-significant bit first across byte boundaries', () => {
		const result = encodeStatusList(131072, [0, 7, 8, 131071]);
		const expected = Buffer.alloc(16384, 0xff);
		expected[0] = 0x7e;
		expected[1] = 0xfe;
		expected[16383] = 0x7f;
		expect(inflateSync(Buffer.from(result.lst, 'base64url'))).toEqual(expected);
	});

	it('accepts streamed indices, tolerates duplicates, and keeps padding invalid', () => {
		function* indices() {
			yield 0;
			yield 8;
			yield 8;
		}
		const result = encodeStatusList(9, indices());
		expect(inflateSync(Buffer.from(result.lst, 'base64url'))).toEqual(Buffer.from([0xfe, 0xfe]));
	});

	it('can mark every position valid without sharing state between calls', () => {
		const first = encodeStatusList(8, [0, 1, 2, 3, 4, 5, 6, 7]);
		const second = encodeStatusList(8, []);
		expect(inflateSync(Buffer.from(first.lst, 'base64url'))).toEqual(Buffer.from([0]));
		expect(inflateSync(Buffer.from(second.lst, 'base64url'))).toEqual(Buffer.from([0xff]));
	});

	it.each([0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects capacity %s', (capacity) => {
		expect(() => encodeStatusList(capacity, [])).toThrow(RangeError);
	});

	it.each([-1, 0.5, 9, NaN, Infinity])('rejects index %s rather than returning a partial list', (idx) => {
		expect(() => encodeStatusList(9, [0, idx])).toThrow(RangeError);
	});
});
