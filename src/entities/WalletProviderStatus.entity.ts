import { randomInt, randomUUID } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { Column, Entity, EntityManager, Index, JoinColumn, ManyToOne, PrimaryColumn, QueryFailedError, Repository } from 'typeorm';
import { Result, Ok, Err } from 'ts-results';
import AppDataSource from '../AppDataSource';
import { logger } from '../logger';

const log = logger.child({ module: 'WalletProviderStatus' });

export type StatusKind = 'wa' | 'ka';

export type WalletProviderStatusReference = {
	id: string;
	idx: number;
	listId: string;
	exp: number;
};

const LIST_ENTRIES = 131072;
const ALLOCATIONS_PER_LIST = 10000;
export const STATUS_MAINTENANCE_SECONDS = 32 * 24 * 60 * 60;
export const STATUS_TOKEN_SECONDS = 60;

export enum WalletProviderStatusErr {
	WALLET_REVOKED = 'WALLET_REVOKED',
	NOT_EXISTS = 'NOT_EXISTS',
	MIGRATION_NOT_APPLIED = 'MIGRATION_NOT_APPLIED',
	DB_ERR = 'DB_ERR',
}

@Entity({ name: 'wallet_provider_status_owner' })
export class WalletProviderStatusOwnerEntity {
	@PrimaryColumn({ type: 'varchar', length: 36 })
	accountId!: string;

	@Column({ type: 'boolean', default: false })
	revoked!: boolean;
}

@Entity({ name: 'wallet_provider_status_cursor' })
export class WalletProviderStatusCursorEntity {
	@PrimaryColumn({ type: 'varchar', length: 2 })
	kind!: StatusKind;

	@Column({ type: 'varchar', length: 36 })
	listId!: string;

	@Column({ type: 'int', unsigned: true, default: 0 })
	allocatedCount!: number;
}

@Entity({ name: 'wallet_provider_status_entry' })
@Index('status_slot', ['listId', 'slot'], { unique: true })
@Index('status_owner', ['accountId'])
export class WalletProviderStatusEntryEntity {
	@PrimaryColumn({ type: 'varchar', length: 36 })
	id!: string;

	@Column({ type: 'varchar', length: 36 })
	accountId!: string;

	// Status evidence survives user deletion; this relation is to the status owner only.
	@ManyToOne(() => WalletProviderStatusOwnerEntity, { nullable: false })
	@JoinColumn({ name: 'accountId', foreignKeyConstraintName: 'status_owner_fk' })
	owner!: WalletProviderStatusOwnerEntity;

	@Column({ type: 'varchar', length: 2 })
	kind!: StatusKind;

	@Column({ type: 'varchar', length: 36 })
	listId!: string;

	@Column({ type: 'int', unsigned: true })
	slot!: number;

	@Column({ type: 'int', unsigned: true })
	maintenanceExp!: number;

	@Column({ type: 'boolean', default: false })
	revoked!: boolean;
}

const walletProviderStatusEntryRepository: Repository<WalletProviderStatusEntryEntity> =
	AppDataSource.getRepository(WalletProviderStatusEntryEntity);

/** Account-wide revocation group; entries and slots are never recycled. */
async function runStatusTransaction<T>(
	operation: (manager: EntityManager) => Promise<Result<T, WalletProviderStatusErr>>,
): Promise<Result<T, WalletProviderStatusErr>> {
	for (let attempt = 0; ; attempt++) {
		try {
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
				log.error({ error }, 'Database error during status transaction');
				return Err(WalletProviderStatusErr.DB_ERR);
			}
			await new Promise((resolve) => setTimeout(resolve, 10 * (attempt + 1) + randomInt(20)));
		}
	}
}

async function lockStatusOwner(manager: EntityManager, accountId: string): Promise<boolean> {
	// Updating only the identifier must never clear an existing revocation flag.
	await manager
		.createQueryBuilder()
		.insert()
		.into(WalletProviderStatusOwnerEntity)
		.values({ accountId })
		.orUpdate(['accountId'], ['accountId'])
		.execute();
	const owner = await manager.findOneOrFail(WalletProviderStatusOwnerEntity, {
		where: { accountId },
		lock: { mode: 'pessimistic_write' },
	});
	return owner.revoked;
}

export async function allocateWalletProviderStatus(
	accountId: string,
	kind: StatusKind,
): Promise<Result<WalletProviderStatusReference, WalletProviderStatusErr>> {
	return runStatusTransaction(async (manager) => {
		if (await lockStatusOwner(manager, accountId)) {
			return Err(WalletProviderStatusErr.WALLET_REVOKED);
		}
		const cursor = await manager.findOne(WalletProviderStatusCursorEntity, {
			where: { kind },
			lock: { mode: 'pessimistic_write' },
		});
		if (!cursor) {
			return Err(WalletProviderStatusErr.MIGRATION_NOT_APPLIED);
		}
		let listId: string = cursor.listId;
		let count: number = cursor.allocatedCount;
		if (count >= ALLOCATIONS_PER_LIST) {
			listId = randomUUID();
			count = 0;
		}
		// The locked cursor serializes allocation. Low occupancy keeps retries small.
		let idx: number;
		let occupied: WalletProviderStatusEntryEntity | null;
		do {
			idx = randomInt(LIST_ENTRIES);
			occupied = await manager.findOne(WalletProviderStatusEntryEntity, {
				where: { listId, slot: idx },
				select: { id: true },
			});
		} while (occupied !== null);
		const id = randomUUID();
		const exp = Math.floor(Date.now() / 1000) + STATUS_MAINTENANCE_SECONDS;
		await manager.insert(WalletProviderStatusEntryEntity, {
			id,
			accountId,
			kind,
			listId,
			slot: idx,
			maintenanceExp: exp,
		});
		await manager.update(
			WalletProviderStatusCursorEntity,
			{ kind },
			{
				listId,
				allocatedCount: count + 1,
			},
		);
		return Ok({ id, idx, listId, exp });
	});
}

export async function revokeWalletProviderStatus(accountId: string): Promise<Result<void, WalletProviderStatusErr>> {
	return runStatusTransaction(async (manager) => {
		await revokeWalletProviderStatusInTransaction(manager, accountId);
		return Ok(undefined);
	});
}

/** Use the caller's transaction so deletion and revocation commit or roll back together. */
export async function revokeWalletProviderStatusInTransaction(manager: EntityManager, accountId: string): Promise<void> {
	await lockStatusOwner(manager, accountId);
	await manager.update(WalletProviderStatusOwnerEntity, { accountId }, { revoked: true });
	await manager.update(WalletProviderStatusEntryEntity, { accountId }, { revoked: true });
}

export async function getWalletProviderStatusList(listId: string): Promise<Result<{ bits: number; lst: string }, WalletProviderStatusErr>> {
	try {
		const entries = await walletProviderStatusEntryRepository.find({
			where: { listId },
			select: { slot: true, revoked: true, maintenanceExp: true },
		});
		if (entries.length === 0) {
			return Err(WalletProviderStatusErr.NOT_EXISTS);
		}
		// Unallocated and expired entries are invalid, never implicitly valid.
		const bytes = Buffer.alloc(LIST_ENTRIES / 8, 0xff);
		const now = Math.floor(Date.now() / 1000);
		for (const entry of entries) {
			if (!entry.revoked && entry.maintenanceExp > now) {
				bytes[Math.floor(entry.slot / 8)] &= ~(1 << (entry.slot % 8));
			}
		}
		return Ok({ bits: 1, lst: deflateSync(bytes).toString('base64url') });
	} catch (error) {
		log.error({ error }, 'Database error during status transaction');
		return Err(WalletProviderStatusErr.DB_ERR);
	}
}
