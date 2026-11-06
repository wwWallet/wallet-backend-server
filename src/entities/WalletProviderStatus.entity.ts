import { randomInt, randomUUID } from 'node:crypto';
import { encodeStatusList } from '../services/StatusListService';
import type { EncodedStatusList } from '../services/StatusListService';
import { ShardCache } from '../status/ShardCache';
import {
	STATUS_CAPACITY,
	STATUS_COLLISION_LIMIT,
	STATUS_INSERT_LIMIT,
	STATUS_MAX_SHARD,
	isStatusSlotCollision,
	isSupportedStatusListId,
	statusListId,
	utcWeekStart,
} from '../status/allocator';
import { Column, Entity, EntityManager, Index, PrimaryColumn, QueryFailedError, Repository } from 'typeorm';
import { Result, Ok, Err } from 'ts-results';
import AppDataSource from '../AppDataSource';
import { logger } from '../logger';
import { UserEntity, UserId } from './user.entity';

const log = logger.child({ module: 'WalletProviderStatus' });

export type StatusType = 'wa' | 'ka';

export type WalletProviderStatusReference = {
	id: string;
	idx: number;
	listId: string;
	maintenanceExpiresAt: number;
};

export const STATUS_MAINTENANCE_SECONDS = 32 * 24 * 60 * 60;
export const STATUS_TOKEN_SECONDS = 60;

export enum WalletProviderStatusErr {
	WALLET_REVOKED = 'WALLET_REVOKED',
	NOT_EXISTS = 'NOT_EXISTS',
	DB_ERR = 'DB_ERR',
	BUSY = 'BUSY',
}

@Entity({ name: 'wallet_provider_status_list_entry' })
@Index('status_slot', ['listId', 'idx'], { unique: true })
@Index('status_account', ['accountId'])
@Index('status_discovery', ['type', 'periodStart', 'shard'])
export class WalletProviderStatusListEntryEntity {
	@PrimaryColumn({ type: 'varchar', length: 36 })
	id!: string;

	@Column({ type: 'varchar', length: 36 })
	accountId!: string;

	@Column({ type: 'varchar', length: 2 })
	type!: StatusType;

	@Column({ type: 'varchar', length: 43, charset: 'ascii', collation: 'ascii_bin' })
	listId!: string;

	@Column({ type: 'date' })
	periodStart!: string;

	@Column({ type: 'int', unsigned: true })
	shard!: number;

	@Column({ type: 'int', unsigned: true })
	idx!: number;

	@Column({ type: 'int', unsigned: true })
	maintenanceExp!: number;

	@Column({ type: 'boolean', default: false })
	revoked!: boolean;
}

const walletProviderStatusListEntryRepository: Repository<WalletProviderStatusListEntryEntity> =
	AppDataSource.getRepository(WalletProviderStatusListEntryEntity);

const shardCache = new ShardCache(async (type, periodStart) => {
	const latest = await walletProviderStatusListEntryRepository.findOne({
		select: { shard: true },
		where: { type, periodStart },
		order: { shard: 'DESC' },
	});
	return latest?.shard ?? 0;
});

/** Account-wide revocation group; entries and slots are never recycled. */
async function runStatusTransaction<T>(
	operation: (manager: EntityManager) => Promise<Result<T, WalletProviderStatusErr>>,
	beforeAttempt?: () => Promise<void>,
): Promise<Result<T, WalletProviderStatusErr>> {
	for (let attempt = 0; ; attempt++) {
		try {
			await beforeAttempt?.();
			// Reads use current committed state; row locks serialize allocation and revocation.
			return await AppDataSource.manager.transaction('READ COMMITTED', async (manager) => {
				const result = await operation(manager);
				if (result.err) {
					throw result;
				}
				return result;
			});
		} catch (error) {
			if (error instanceof Err) {
				return error;
			}
			const code = error instanceof QueryFailedError ? error.driverError.code : undefined;
			// Retry the whole rolled-back transaction, never an individual write.
			if (attempt >= 4 || !['ER_CHECKREAD', 'ER_LOCK_DEADLOCK', 'ER_LOCK_WAIT_TIMEOUT'].includes(code)) {
				log.error({ code }, 'Database error during status transaction');
				return Err(WalletProviderStatusErr.DB_ERR);
			}
			await new Promise((resolve) => setTimeout(resolve, 10 * (attempt + 1) + randomInt(20)));
		}
	}
}

async function lockUserAndCheckStatusRevocation(manager: EntityManager, accountId: string): Promise<boolean> {
	const user = await manager.findOne(UserEntity, {
		select: { uuid: true, isRevoked: true },
		where: { uuid: UserId.fromId(accountId) },
		loadEagerRelations: false,
		lock: { mode: 'pessimistic_write' },
	});
	return !user || user.isRevoked;
}

export async function allocateWalletProviderStatus(
	accountId: string,
	type: StatusType,
): Promise<Result<WalletProviderStatusReference, WalletProviderStatusErr>> {
	const periodStart = utcWeekStart(new Date());
	let shard = 0;
	let lastAttemptedShard = 0;
	const allocate = () =>
		runStatusTransaction(
			async (manager) => {
				if (await lockUserAndCheckStatusRevocation(manager, accountId)) {
					return Err(WalletProviderStatusErr.WALLET_REVOKED);
				}
				for (let attempt = 0; attempt < STATUS_INSERT_LIMIT; attempt++) {
					lastAttemptedShard = shard;
					const listId = statusListId(type, periodStart, shard);
					const idx = randomInt(STATUS_CAPACITY);
					const id = randomUUID();
					const maintenanceExpiresAt = Math.floor(Date.now() / 1000) + STATUS_MAINTENANCE_SECONDS;
					try {
						await manager.insert(WalletProviderStatusListEntryEntity, {
							id,
							accountId,
							type,
							listId,
							idx,
							maintenanceExp: maintenanceExpiresAt,
							periodStart,
							shard,
						});
						return Ok({ id, idx, listId, maintenanceExpiresAt });
					} catch (error) {
						if (!isStatusSlotCollision(error)) {
							throw error;
						}
						if ((attempt + 1) % STATUS_COLLISION_LIMIT === 0) {
							if (shard === STATUS_MAX_SHARD) {
								return Err(WalletProviderStatusErr.BUSY);
							}
							shard++;
						}
					}
				}
				return Err(WalletProviderStatusErr.BUSY);
			},
			async () => {
				shard = await shardCache.get(type, periodStart);
			},
		);
	let result = await allocate();
	if (result.err && result.val === WalletProviderStatusErr.BUSY) {
		// Another process may have advanced further. Refresh once, outside the rolled-back transaction.
		try {
			const latest = await shardCache.get(type, periodStart, true);
			if (latest > lastAttemptedShard) {
				result = await allocate();
			}
		} catch (error) {
			log.error({ code: error instanceof QueryFailedError ? error.driverError.code : undefined }, 'Database error refreshing status shard');
			return Err(WalletProviderStatusErr.DB_ERR);
		}
	}
	if (result.ok) {
		shardCache.remember(type, periodStart, shard);
	}
	return result;
}

export async function revokeWalletProviderStatusesForAccount(accountId: string): Promise<Result<void, WalletProviderStatusErr>> {
	return runStatusTransaction(async (manager) => {
		await revokeWalletProviderStatusesForAccountInTransaction(manager, accountId);
		return Ok(undefined);
	});
}

/** Use the caller's transaction so deletion and revocation commit or roll back together. */
export async function revokeWalletProviderStatusesForAccountInTransaction(manager: EntityManager, accountId: string): Promise<void> {
	await lockUserAndCheckStatusRevocation(manager, accountId);
	await manager.update(UserEntity, { uuid: UserId.fromId(accountId) }, { isRevoked: true });
	await manager.update(WalletProviderStatusListEntryEntity, { accountId }, { revoked: true });
}

export async function getWalletProviderStatusList(listId: string): Promise<Result<EncodedStatusList, WalletProviderStatusErr>> {
	try {
		if (!isSupportedStatusListId(listId)) {
			return Err(WalletProviderStatusErr.NOT_EXISTS);
		}
		// A single joined read keeps user revocation and entry state consistent.
		const entries = await walletProviderStatusListEntryRepository
			.createQueryBuilder('entry')
			.leftJoin(UserEntity, 'account', 'account.uuid = entry.accountId')
			.select('entry.idx', 'idx')
			.addSelect('entry.revoked', 'revoked')
			.addSelect('entry.maintenanceExp', 'maintenanceExp')
			.addSelect('account.isRevoked', 'userRevoked')
			.where('entry.listId = :listId', { listId })
			.getRawMany<{
				idx: number;
				revoked: number;
				maintenanceExp: number;
				userRevoked: number | null;
			}>();
		if (entries.length === 0) {
			return Err(WalletProviderStatusErr.NOT_EXISTS);
		}
		const now = Math.floor(Date.now() / 1000);
		const validIndices = entries
			.filter((entry) => entry.userRevoked === 0 && entry.revoked === 0 && entry.maintenanceExp > now)
			.map((entry) => entry.idx);
		return Ok(encodeStatusList(STATUS_CAPACITY, validIndices));
	} catch (error) {
		log.error(
			{
				code: error instanceof QueryFailedError ? error.driverError.code : undefined,
			},
			'Database error publishing status list',
		);
		return Err(WalletProviderStatusErr.DB_ERR);
	}
}
