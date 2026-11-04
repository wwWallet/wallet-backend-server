import 'reflect-metadata';
import { inflateSync } from 'node:zlib';
import { DataSource } from 'typeorm';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ transaction: vi.fn(), repository: { createQueryBuilder: vi.fn() } }));
vi.mock('../AppDataSource', () => ({
	default: { manager: { transaction: mocks.transaction }, getRepository: () => mocks.repository },
}));
vi.mock('../logger', () => ({ logger: { child: () => ({ error: vi.fn() }) } }));

import {
	allocateWalletProviderStatus,
	getWalletProviderStatusList,
	revokeWalletProviderStatus,
	WalletProviderStatusCursorEntity,
	WalletProviderStatusEntryEntity,
	WalletProviderStatusErr,
} from './WalletProviderStatus.entity';
import { UserEntity, UserId, WebauthnCredentialEntity } from './user.entity';

const accountId = 'test-account';

beforeEach(() => vi.clearAllMocks());

describe('user-backed status allocation and revocation', () => {
	function setup(user: { isRevoked: boolean } | null) {
		const manager = {
			findOne: vi.fn(async (entity: unknown) => (entity === UserEntity ? user : { listId: 'list', allocatedCount: 0 })),
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

	it('locks an active user before allocating a status entry', async () => {
		const manager = setup({ isRevoked: false });
		manager.findOne.mockImplementation(async (entity) => {
			if (entity === UserEntity) return { isRevoked: false };
			if (entity === WalletProviderStatusCursorEntity) return { listId: 'list', allocatedCount: 0 };
			return null;
		});
		const result = await allocateWalletProviderStatus(accountId, 'wa');
		expect(result.ok).toBe(true);
		expect(manager.insert).toHaveBeenCalledWith(WalletProviderStatusEntryEntity, expect.objectContaining({ accountId }));
		expect(manager.findOne.mock.calls[0][0]).toBe(UserEntity);
	});

	it.each([null, { isRevoked: false }])('revokes existing entries even if the user is missing: %j', async (user) => {
		const manager = setup(user);
		const result = await revokeWalletProviderStatus(accountId);
		expect(result.ok).toBe(true);
		expect(manager.update.mock.calls).toEqual([
			[UserEntity, { uuid: UserId.fromId(accountId) }, { isRevoked: true }],
			[WalletProviderStatusEntryEntity, { accountId }, { revoked: true }],
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
				{ slot: 0, revoked: 0, maintenanceExp: now + 60, userRevoked: 0 },
				{ slot: 1, revoked: 0, maintenanceExp: now + 60, userRevoked: null },
				{ slot: 2, revoked: 0, maintenanceExp: now + 60, userRevoked: 1 },
				{ slot: 3, revoked: 1, maintenanceExp: now + 60, userRevoked: 0 },
				{ slot: 4, revoked: 0, maintenanceExp: now - 60, userRevoked: 0 },
			]),
		};
		mocks.repository.createQueryBuilder.mockReturnValue(query);
		const result = await getWalletProviderStatusList('list');
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('Expected status list');
		const bytes = inflateSync(Buffer.from(result.val.lst, 'base64url'));
		expect(bytes[0]).toBe(0xfe);
		expect(bytes[1]).toBe(0xff);
		expect(query.leftJoin).toHaveBeenCalledWith(UserEntity, 'account', 'account.uuid = entry.accountId');
	});

	it('generates the join against the indexed database user identifier', async () => {
		const source = new DataSource({
			type: 'mysql',
			database: 'status_test',
			entities: [UserEntity, WebauthnCredentialEntity, WalletProviderStatusEntryEntity, WalletProviderStatusCursorEntity],
		});
		// Build real MySQL metadata/query SQL without opening a database connection.
		await (source as unknown as { buildMetadatas(): Promise<void> }).buildMetadatas();
		const builder = source.getRepository(WalletProviderStatusEntryEntity).createQueryBuilder('entry');
		mocks.repository.createQueryBuilder.mockReturnValue(builder);
		vi.spyOn(builder, 'getRawMany').mockResolvedValue([]);
		await getWalletProviderStatusList('list');
		expect(builder.getSql()).toContain('`account`.`webauthnUserHandle` = `entry`.`accountId`');
		const user = source.getMetadata(UserEntity);
		expect(user.indices.some((index) => index.isUnique && index.columns.some((column) => column.propertyName === 'uuid'))).toBe(true);
		const entry = source.getMetadata(WalletProviderStatusEntryEntity);
		expect(entry.foreignKeys).toHaveLength(0);
		expect(entry.indices.some((index) => index.columns.some((column) => column.propertyName === 'accountId'))).toBe(true);
	});
});
