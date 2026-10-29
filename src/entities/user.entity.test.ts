import 'reflect-metadata';
import type { EntityManager } from 'typeorm';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ transaction: vi.fn() }));
vi.mock('../AppDataSource', () => ({
	default: { getRepository: () => ({ manager: { transaction: mocks.transaction } }) },
}));
vi.mock('../logger', () => ({ logger: { child: () => ({ error: vi.fn() }) } }));

import { deleteUser, UserEntity, UserId } from './user.entity';
import { WalletProviderStatusEntryEntity, WalletProviderStatusOwnerEntity } from './WalletProviderStatus.entity';

describe('user deletion revocation', () => {
	const accountId = 'deleted-account';
	let manager: EntityManager;
	let update: ReturnType<typeof vi.fn>;
	let remove: ReturnType<typeof vi.fn>;
	let ownerLookup: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		vi.clearAllMocks();
		const insert = {
			insert: vi.fn().mockReturnThis(),
			into: vi.fn().mockReturnThis(),
			values: vi.fn().mockReturnThis(),
			orUpdate: vi.fn().mockReturnThis(),
			execute: vi.fn().mockResolvedValue({}),
		};
		update = vi.fn().mockResolvedValue({});
		remove = vi.fn().mockResolvedValue({});
		ownerLookup = vi.fn().mockResolvedValue({ accountId, revoked: false });
		manager = {
			createQueryBuilder: () => insert,
			findOneOrFail: ownerLookup,
			findOne: vi.fn().mockResolvedValue({ uuid: UserId.fromId(accountId) }),
			update,
			delete: remove,
		} as unknown as EntityManager;
		mocks.transaction.mockImplementation(async (operation) => operation(manager));
	});

	it('revokes the owner and all entries before deleting user data in the same transaction', async () => {
		const result = await deleteUser(UserId.fromId(accountId));
		expect(result.ok).toBe(true);
		expect(ownerLookup).toHaveBeenCalledWith(WalletProviderStatusOwnerEntity, {
			where: { accountId },
			lock: { mode: 'pessimistic_write' },
		});
		expect(update.mock.calls).toEqual([
			[WalletProviderStatusOwnerEntity, { accountId }, { revoked: true }],
			[WalletProviderStatusEntryEntity, { accountId }, { revoked: true }],
		]);
		expect(update.mock.invocationCallOrder[1]).toBeLessThan(remove.mock.invocationCallOrder[0]);
		expect(remove).toHaveBeenCalledWith(UserEntity, { uuid: UserId.fromId(accountId) });
		expect(
			remove.mock.calls.some(([entity]) => entity === WalletProviderStatusOwnerEntity || entity === WalletProviderStatusEntryEntity),
		).toBe(false);
	});

	it('aborts the deletion transaction if revocation fails', async () => {
		const failure = new Error('status write failed');
		update.mockRejectedValueOnce(failure);
		const result = await deleteUser(UserId.fromId(accountId));
		expect(result.err).toBe(true);
		expect(remove).not.toHaveBeenCalled();
		await expect(mocks.transaction.mock.results[0].value).rejects.toThrow(failure);
	});

	it('propagates deletion failure out of the transaction so revocation can roll back', async () => {
		const failure = new Error('user delete failed');
		remove.mockRejectedValueOnce(failure);
		const result = await deleteUser(UserId.fromId(accountId));
		expect(result.err).toBe(true);
		await expect(mocks.transaction.mock.results[0].value).rejects.toThrow(failure);
	});

	it('uses the supplied transaction manager when deletion is part of a larger transaction', async () => {
		const transaction = vi.fn(async (operation) => operation(manager));
		const result = await deleteUser(UserId.fromId(accountId), {
			entityManager: { transaction } as unknown as EntityManager,
		});
		expect(result.ok).toBe(true);
		expect(transaction).toHaveBeenCalledOnce();
		expect(mocks.transaction).not.toHaveBeenCalled();
		expect(update).toHaveBeenCalledWith(WalletProviderStatusEntryEntity, { accountId }, { revoked: true });
	});
});
