import 'reflect-metadata';
import { inflateSync } from 'node:zlib';
import { DataSource, QueryFailedError } from 'typeorm';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ transaction: vi.fn(), repository: { createQueryBuilder: vi.fn(), findOne: vi.fn() } }));
vi.mock('../AppDataSource', () => ({
	default: { manager: { transaction: mocks.transaction }, getRepository: () => mocks.repository },
}));
vi.mock('../logger', () => ({ logger: { child: () => ({ error: vi.fn() }) } }));

import {
	allocateWalletProviderStatus,
	getWalletProviderStatusList,
	revokeWalletProviderStatusesForAccount,
	WalletProviderStatusListEntryEntity,
	WalletProviderStatusErr,
} from './WalletProviderStatus.entity';
import { STATUS_MAX_SHARD, statusListId, utcWeekStart } from '../status/allocator';
import { UserEntity, UserId, WebauthnCredentialEntity } from './user.entity';

const accountId = 'test-account';
const listId = statusListId('wa', '2026-11-02', 0);

let testWeek = 0;
beforeEach(() => {
	vi.useFakeTimers({ toFake: ['Date'] });
	vi.setSystemTime(new Date(Date.UTC(2030, 0, 7 + 7 * testWeek++)));
	vi.clearAllMocks();
	mocks.repository.findOne.mockResolvedValue(null);
});

afterEach(() => vi.useRealTimers());

describe('user-backed status allocation and revocation', () => {
	function setup(user: { isRevoked: boolean } | null) {
		const manager = {
			findOne: vi.fn().mockResolvedValue(user),
			insert: vi.fn().mockResolvedValue({}),
			update: vi.fn().mockResolvedValue({}),
		};
		mocks.transaction.mockImplementation(async (_isolation, operation) => operation(manager));
		return manager;
	}

	it.each([null, { isRevoked: true }])('rejects allocation for missing/revoked users: %j', async (user) => {
		const manager = setup(user);
		const result = await allocateWalletProviderStatus(accountId, 'wa');
		expect(result.err && result.val).toBe(WalletProviderStatusErr.WALLET_REVOKED);
		expect(manager.findOne).toHaveBeenCalledExactlyOnceWith(UserEntity, {
			where: { uuid: UserId.fromId(accountId) },
			select: { uuid: true, isRevoked: true },
			loadEagerRelations: false,
			lock: { mode: 'pessimistic_write' },
		});
		expect(manager.insert).not.toHaveBeenCalled();
		expect(manager.update).not.toHaveBeenCalled();
	});

	it.each(['wa', 'ka'] as const)('locks an active user and allocates a status entry of type %s', async (type) => {
		const manager = setup({ isRevoked: false });
		const result = await allocateWalletProviderStatus(accountId, type);
		expect(result.ok).toBe(true);
		expect(manager.insert).toHaveBeenCalledWith(WalletProviderStatusListEntryEntity, expect.objectContaining({ accountId, type }));
		expect(mocks.repository.findOne).toHaveBeenCalledWith(
			expect.objectContaining({ where: { type, periodStart: utcWeekStart(new Date()) } }),
		);
		expect(manager.findOne.mock.calls[0][0]).toBe(UserEntity);
	});

	function failure(code = 'ER_DUP_ENTRY', key = 'status_slot') {
		return new QueryFailedError(
			'INSERT',
			[],
			Object.assign(new Error(), {
				code,
				sqlMessage: `Duplicate entry 'value' for key '${key}'`,
			}),
		);
	}

	it('advances after five collisions and starts the next request at the cached committed shard', async () => {
		const manager = setup({ isRevoked: false });
		mocks.repository.findOne.mockResolvedValue({ shard: 100 });
		for (let i = 0; i < 5; i++) manager.insert.mockRejectedValueOnce(failure());
		expect((await allocateWalletProviderStatus(accountId, 'wa')).ok).toBe(true);
		expect(manager.insert).toHaveBeenCalledTimes(6);
		expect(manager.insert.mock.calls.map((call) => call[1].shard)).toEqual([100, 100, 100, 100, 100, 101]);
		expect(manager.findOne).toHaveBeenCalledTimes(1);
		expect(manager.update).not.toHaveBeenCalled();
		await allocateWalletProviderStatus(accountId, 'wa');
		expect(manager.insert.mock.lastCall?.[1].shard).toBe(101);
		expect(mocks.repository.findOne).toHaveBeenCalledTimes(1);
	});

	it('can allocate on the fiftieth insertion attempt', async () => {
		const manager = setup({ isRevoked: false });
		for (let i = 0; i < 49; i++) manager.insert.mockRejectedValueOnce(failure());
		expect((await allocateWalletProviderStatus(accountId, 'wa')).ok).toBe(true);
		expect(manager.insert).toHaveBeenCalledTimes(50);
		expect(manager.insert.mock.lastCall?.[1].shard).toBe(9);
		expect(mocks.repository.findOne).toHaveBeenCalledTimes(1);
	});

	it('bounds collision work to fifty inserts and rolls back as BUSY', async () => {
		const manager = setup({ isRevoked: false });
		manager.insert.mockRejectedValue(failure());
		expect((await allocateWalletProviderStatus(accountId, 'wa')).val).toBe(WalletProviderStatusErr.BUSY);
		expect(manager.insert).toHaveBeenCalledTimes(50);
		expect(new Set(manager.insert.mock.calls.map((call) => call[1].shard))).toEqual(new Set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]));
		expect(mocks.transaction).toHaveBeenCalledTimes(1);
		await expect(mocks.transaction.mock.results[0].value).rejects.toMatchObject({ val: WalletProviderStatusErr.BUSY });
	});

	it('refreshes a stale shard after collision exhaustion and retries on a newer shard', async () => {
		const manager = setup({ isRevoked: false });
		mocks.repository.findOne.mockResolvedValueOnce({ shard: 0 }).mockResolvedValueOnce({ shard: 100 });
		for (let i = 0; i < 50; i++) manager.insert.mockRejectedValueOnce(failure());
		expect((await allocateWalletProviderStatus(accountId, 'wa')).ok).toBe(true);
		expect(manager.insert).toHaveBeenCalledTimes(51);
		expect(manager.insert.mock.lastCall?.[1].shard).toBe(100);
		expect(mocks.repository.findOne).toHaveBeenCalledTimes(2);
	});

	it('returns DB_ERR if discovery refresh fails after collision exhaustion', async () => {
		const manager = setup({ isRevoked: false });
		mocks.repository.findOne.mockResolvedValueOnce(null).mockRejectedValueOnce(new Error('database unavailable'));
		manager.insert.mockRejectedValue(failure());
		expect((await allocateWalletProviderStatus(accountId, 'wa')).val).toBe(WalletProviderStatusErr.DB_ERR);
		expect(manager.insert).toHaveBeenCalledTimes(50);
	});

	it('bounds collision work after refreshing to another busy shard', async () => {
		const manager = setup({ isRevoked: false });
		mocks.repository.findOne.mockResolvedValueOnce(null).mockResolvedValueOnce({ shard: 100 });
		manager.insert.mockRejectedValue(failure());
		expect((await allocateWalletProviderStatus(accountId, 'wa')).val).toBe(WalletProviderStatusErr.BUSY);
		expect(manager.insert).toHaveBeenCalledTimes(100);
		expect(mocks.repository.findOne).toHaveBeenCalledTimes(2);
	});

	it('does not cache a shard advance from a failed commit', async () => {
		const manager = setup({ isRevoked: false });
		for (let i = 0; i < 5; i++) manager.insert.mockRejectedValueOnce(failure());
		mocks.transaction.mockImplementationOnce(async (_isolation, operation) => {
			await operation(manager);
			throw failure('ER_UNKNOWN_ERROR');
		});
		expect((await allocateWalletProviderStatus(accountId, 'wa')).val).toBe(WalletProviderStatusErr.DB_ERR);
		expect((await allocateWalletProviderStatus(accountId, 'wa')).ok).toBe(true);
		expect(manager.insert.mock.lastCall?.[1].shard).toBe(0);
	});

	it('does not treat another unique constraint as a slot collision', async () => {
		const manager = setup({ isRevoked: false });
		manager.insert.mockRejectedValue(failure('ER_DUP_ENTRY', 'PRIMARY'));
		expect((await allocateWalletProviderStatus(accountId, 'wa')).val).toBe(WalletProviderStatusErr.DB_ERR);
		expect(manager.insert).toHaveBeenCalledTimes(1);
	});

	it('bounds deadlock and timeout retries to five whole transactions', async () => {
		const manager = setup({ isRevoked: false });
		manager.insert.mockRejectedValue(failure('ER_LOCK_WAIT_TIMEOUT'));
		expect((await allocateWalletProviderStatus(accountId, 'wa')).val).toBe(WalletProviderStatusErr.DB_ERR);
		expect(mocks.transaction).toHaveBeenCalledTimes(5);
		expect(mocks.repository.findOne).toHaveBeenCalledTimes(1);
	});

	it('returns BUSY rather than overflowing the shard column', async () => {
		const manager = setup({ isRevoked: false });
		mocks.repository.findOne.mockResolvedValue({ shard: STATUS_MAX_SHARD });
		manager.insert.mockRejectedValue(failure());
		expect((await allocateWalletProviderStatus(accountId, 'wa')).val).toBe(WalletProviderStatusErr.BUSY);
		expect(manager.insert).toHaveBeenCalledTimes(5);
	});

	it('reuses discovery and rechecks revocation after a deadlock', async () => {
		const manager = setup({ isRevoked: false });
		manager.insert.mockRejectedValueOnce(failure('ER_LOCK_DEADLOCK'));
		manager.findOne.mockResolvedValueOnce({ isRevoked: false }).mockResolvedValueOnce({ isRevoked: true });
		expect((await allocateWalletProviderStatus(accountId, 'wa')).val).toBe(WalletProviderStatusErr.WALLET_REVOKED);
		expect(mocks.repository.findOne).toHaveBeenCalledTimes(1);
		expect(manager.findOne).toHaveBeenCalledTimes(2);
		expect(manager.insert).toHaveBeenCalledTimes(1);
	});

	it('keeps the captured period when a transaction retry crosses Monday', async () => {
		const manager = setup({ isRevoked: false });
		vi.useFakeTimers({ toFake: ['Date'] });
		vi.setSystemTime(new Date('2026-11-08T23:59:59Z'));
		const before = utcWeekStart(new Date());
		manager.insert.mockImplementationOnce(async () => {
			vi.setSystemTime(new Date('2026-11-09T00:00:01Z'));
			throw failure('ER_LOCK_DEADLOCK');
		});
		try {
			expect((await allocateWalletProviderStatus(accountId, 'wa')).ok).toBe(true);
			expect(manager.insert.mock.calls.every((call) => call[1].periodStart === before)).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	it.each([null, { isRevoked: false }])('revokes existing entries even if the user is missing: %j', async (user) => {
		const manager = setup(user);
		const result = await revokeWalletProviderStatusesForAccount(accountId);
		expect(result.ok).toBe(true);
		expect(manager.update.mock.calls).toEqual([
			[UserEntity, { uuid: UserId.fromId(accountId) }, { isRevoked: true }],
			[WalletProviderStatusListEntryEntity, { accountId }, { revoked: true }],
		]);
		expect(manager.findOne.mock.invocationCallOrder[0]).toBeLessThan(manager.update.mock.invocationCallOrder[0]);
	});
});

describe('status lists', () => {
	it('revokes missing/revoked users and expired/revoked entries while preserving active entries', async () => {
		const now = Math.floor(Date.now() / 1000);
		const query = {
			leftJoin: vi.fn().mockReturnThis(),
			select: vi.fn().mockReturnThis(),
			addSelect: vi.fn().mockReturnThis(),
			where: vi.fn().mockReturnThis(),
			getRawMany: vi.fn().mockResolvedValue([
				{ idx: 0, revoked: 0, maintenanceExp: now + 60, userRevoked: 0 },
				{ idx: 1, revoked: 0, maintenanceExp: now + 60, userRevoked: null },
				{ idx: 2, revoked: 0, maintenanceExp: now + 60, userRevoked: 1 },
				{ idx: 3, revoked: 1, maintenanceExp: now + 60, userRevoked: 0 },
				{ idx: 4, revoked: 0, maintenanceExp: now - 60, userRevoked: 0 },
			]),
		};
		mocks.repository.createQueryBuilder.mockReturnValue(query);
		const result = await getWalletProviderStatusList(listId);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('Expected status list');
		const bytes = inflateSync(Buffer.from(result.val.lst, 'base64url'));
		expect(bytes[0]).toBe(0xfe);
		expect(bytes[1]).toBe(0xff);
		expect(query.leftJoin).toHaveBeenCalledWith(UserEntity, 'account', 'account.uuid = entry.accountId');
	});

	it('preserves one-bit wire encoding at byte boundaries and the last position', async () => {
		const now = Math.floor(Date.now() / 1000);
		const query = {
			leftJoin: vi.fn().mockReturnThis(),
			select: vi.fn().mockReturnThis(),
			addSelect: vi.fn().mockReturnThis(),
			where: vi.fn().mockReturnThis(),
			getRawMany: vi
				.fn()
				.mockResolvedValue([0, 7, 8, 131071].map((idx) => ({ idx, revoked: 0, maintenanceExp: now + 60, userRevoked: 0 }))),
		};
		mocks.repository.createQueryBuilder.mockReturnValue(query);
		const result = await getWalletProviderStatusList(listId);
		if (!result.ok) throw new Error('Expected status list');
		const expected = Buffer.alloc(16384, 0xff);
		expected[0] = 0x7e;
		expected[1] = 0xfe;
		expected[16383] = 0x7f;
		expect(inflateSync(Buffer.from(result.val.lst, 'base64url'))).toEqual(expected);
	});

	it('publishes an existing list with no eligible entries as entirely invalid', async () => {
		const now = Math.floor(Date.now() / 1000);
		const query = {
			leftJoin: vi.fn().mockReturnThis(),
			select: vi.fn().mockReturnThis(),
			addSelect: vi.fn().mockReturnThis(),
			where: vi.fn().mockReturnThis(),
			getRawMany: vi.fn().mockResolvedValue([
				{ idx: 0, revoked: 0, maintenanceExp: now, userRevoked: 0 },
				{ idx: 7, revoked: 1, maintenanceExp: now + 60, userRevoked: 0 },
				{ idx: 8, revoked: 0, maintenanceExp: now + 60, userRevoked: null },
				{ idx: 131071, revoked: 0, maintenanceExp: now + 60, userRevoked: 1 },
			]),
		};
		mocks.repository.createQueryBuilder.mockReturnValue(query);
		const result = await getWalletProviderStatusList(listId);
		if (!result.ok) throw new Error('Expected status list');
		expect(result.val.bits).toBe(1);
		// Decode with native zlib and inspect bytes independently of OWF.
		expect(inflateSync(Buffer.from(result.val.lst, 'base64url'))).toEqual(Buffer.alloc(16384, 0xff));
	});

	it.each([-1, 0.5, 131072])('fails publication for invalid eligible index %s', async (idx) => {
		const query = {
			leftJoin: vi.fn().mockReturnThis(),
			select: vi.fn().mockReturnThis(),
			addSelect: vi.fn().mockReturnThis(),
			where: vi.fn().mockReturnThis(),
			getRawMany: vi.fn().mockResolvedValue([{ idx, revoked: 0, maintenanceExp: Math.floor(Date.now() / 1000) + 60, userRevoked: 0 }]),
		};
		mocks.repository.createQueryBuilder.mockReturnValue(query);
		expect((await getWalletProviderStatusList(listId)).val).toBe(WalletProviderStatusErr.DB_ERR);
	});

	it('returns NOT_EXISTS when no entries exist', async () => {
		const query = {
			leftJoin: vi.fn().mockReturnThis(),
			select: vi.fn().mockReturnThis(),
			addSelect: vi.fn().mockReturnThis(),
			where: vi.fn().mockReturnThis(),
			getRawMany: vi.fn().mockResolvedValue([]),
		};
		mocks.repository.createQueryBuilder.mockReturnValue(query);
		expect((await getWalletProviderStatusList(listId)).val).toBe(WalletProviderStatusErr.NOT_EXISTS);
	});

	it('generates the join against the indexed database user identifier', async () => {
		const source = new DataSource({
			type: 'mysql',
			database: 'status_test',
			entities: [UserEntity, WebauthnCredentialEntity, WalletProviderStatusListEntryEntity],
		});
		// Build real MySQL metadata/query SQL without opening a database connection.
		await (source as unknown as { buildMetadatas(): Promise<void> }).buildMetadatas();
		const builder = source.getRepository(WalletProviderStatusListEntryEntity).createQueryBuilder('entry');
		mocks.repository.createQueryBuilder.mockReturnValue(builder);
		vi.spyOn(builder, 'getRawMany').mockResolvedValue([]);
		await getWalletProviderStatusList(listId);
		expect(builder.getSql()).toContain('`account`.`webauthnUserHandle` = `entry`.`accountId`');
		const user = source.getMetadata(UserEntity);
		expect(user.indices.some((index) => index.isUnique && index.columns.some((column) => column.propertyName === 'uuid'))).toBe(true);
		const entry = source.getMetadata(WalletProviderStatusListEntryEntity);
		expect(entry.foreignKeys).toHaveLength(0);
		expect(entry.indices.some((index) => index.columns.some((column) => column.propertyName === 'accountId'))).toBe(true);
	});
});
