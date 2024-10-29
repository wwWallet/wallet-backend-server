import { Err, Ok, Result } from "ts-results";
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany, Repository, EntityManager, DeepPartial, Generated, Equal } from "typeorm"
import crypto from "node:crypto";
import base64url from "base64url";
import * as uuid from 'uuid';

import AppDataSource from "../AppDataSource";
import * as scrypt from "../scrypt";
import { FcmTokenEntity } from "./FcmToken.entity";
import { checkedUpdate, EtagUpdate, isResult } from "../util/util";
import { runTransaction } from "./common.entity";

export enum WalletType {
	DB,
	CLIENT
}


/**
 * Compute a value suitable to use as an ETag-style HTTP header for the private data field.
 */
export function privateDataEtag(privateData: Buffer): string {
	const etag = base64url.toBase64(base64url.encode(crypto.createHash('sha256').update(privateData).digest()));
	return `"${etag}"`;
}


// Duplicated in wallet-frontend
export class UserId {
	public readonly id: string;
	private constructor(id: string) {
		this.id = id;
	}

	public toString(): string {
		return `UserId(this.id)`;
	}

	public toJSON(): string {
		return this.id;
	}

	static generate(): UserId {
		return new UserId(uuid.v4());
	}

	static fromId(id: string): UserId {
		return new UserId(id);
	}

	static fromUserHandle(userHandle: Buffer): UserId {
		return new UserId(userHandle.toString());
	}

	public asUserHandle(): Buffer {
		return Buffer.from(this.id, "utf8");
	}
}


@Entity({ name: "user" })
class UserEntity {
	/**
	 * This was obsoleted by PR (TBD).
	 * We keep the table column for forward- and backwards compatibility between application and schema versions.
	 * It still needs to be the primary ID in order for table relations to continue working.
	 */
	@Column({ primary: true, unique: true, nullable: false, update: false })
	@Generated("increment")
	private id: number;

	/**
	 * This was renamed in PR (TBD).
	 * We keep the old database column name for forward- and backwards compatibility between application and schema versions.
	 */
	@Column({
		unique: true,
		nullable: false,
		update: false,
		name: "webauthnUserHandle",
		type: "varchar",
		length: 36,
		transformer: { from: UserId.fromId, to: (userId: UserId) => userId.id },
	})
	uuid: UserId;

	// Explicit default to workaround a bug in typeorm: https://github.com/typeorm/typeorm/issues/3076#issuecomment-703128687
	@Column({ unique: true, nullable: true, default: () => "NULL" })
	username: string;

	// Explicit default to workaround a bug in typeorm: https://github.com/typeorm/typeorm/issues/3076#issuecomment-703128687
	@Column({ unique: false, nullable: true, default: () => "NULL" })
	displayName: string;

	@Column({ unique: true, nullable: false })
	did: string;

	// Explicit default to workaround a bug in typeorm: https://github.com/typeorm/typeorm/issues/3076#issuecomment-703128687
	@Column({ nullable: true, default: () => "NULL" })
	passwordHash: string;


	@Column({ type: 'blob', nullable: false })
	keys: Buffer;


	@Column({ type: "bool", default: false })
	isAdmin: boolean = false;

	@Column({ type: "blob", nullable: false })
	privateData: Buffer;


	@Column({ type: "enum" ,enum: WalletType, default: WalletType.DB })
	walletType: WalletType;

	@OneToMany(
		() => WebauthnCredentialEntity, (credential) => credential.user,
		{ cascade: true, onDelete: "CASCADE", orphanedRowAction: "delete", eager: true, nullable: false })
	webauthnCredentials: WebauthnCredentialEntity[];


	@OneToMany(() => FcmTokenEntity, (fcmToken) => fcmToken.user, { eager: true })
	fcmTokenList: FcmTokenEntity[];

	@Column({ nullable: false, default: 0 })
	openidRefreshTokenMaxAgeInSeconds: number;
}

@Entity({ name: "webauthn_credential" })
class WebauthnCredentialEntity {
	@PrimaryGeneratedColumn("uuid")
	id: string;

	@ManyToOne(() => UserEntity, (user) => user.webauthnCredentials, { nullable: false })
	user: UserEntity;

	@Column({ nullable: false, update: false })
	credentialId: Buffer;

	/**
	 * This was obsoleted by PR (TBD).
	 * We keep the table column for forward- and backwards compatibility between application and schema versions.
	 */
	@Column({ name: "userHandle", nullable: false, select: false, update: false })
	_userHandle: Buffer;

	// Explicit default to workaround a bug in typeorm: https://github.com/typeorm/typeorm/issues/3076#issuecomment-703128687
	@Column({ nullable: true, default: () => "NULL" })
	nickname: string;

	@Column({ type: "datetime", nullable: false, update: false })
	createTime: Date;

	@Column({ type: "datetime", nullable: false })
	lastUseTime: Date;

	@Column({ nullable: false, update: false })
	publicKeyCose: Buffer;

	@Column({ nullable: false })
	signatureCount: number = 0;

	@Column("simple-json", { nullable: false })
	transports: string[];

	@Column({ nullable: false, update: false })
	attestationObject: Buffer;

	@Column({ nullable: false, update: false })
	create_clientDataJSON: Buffer;

	@Column({ nullable: false })
	prfCapable: boolean;

	getCredentialDescriptor() {
		return {
			type: "public-key",
			id: this.credentialId,
			transports: this.transports || [],
		};
	}
}


type CreateUser = {
	username: string;
	displayName: string,
	passwordHash: string;
	fcmToken: string;
	privateData: Buffer;
} | {
	uuid: UserId;
	displayName: string,
	keys: Buffer;
	fcmToken: string;
	privateData: Buffer;
	webauthnCredentials: WebauthnCredentialEntity[];
}


enum CreateUserErr {
	ALREADY_EXISTS = "ALREADY_EXISTS"
}

enum GetUserErr {
	NOT_EXISTS = "NOT_EXISTS",
	DB_ERR = "DB_ERR"
}

enum UpdateUserErr {
	NOT_EXISTS = "NOT_EXISTS",
	DB_ERR = "DB_ERR",
	LAST_WEBAUTHN_CREDENTIAL = "LAST_WEBAUTHN_CREDENTIAL",
	PRIVATE_DATA_CONFLICT = "PRIVATE_DATA_CONFLICT",
}

enum UpdateFcmError {
	DB_ERR = "Failed to update FCM token list"
}

enum DeleteUserErr {
	FAILED_TO_DELETE = "FAILED_TO_DELETE"
}


const userRepository: Repository<UserEntity> = AppDataSource.getRepository(UserEntity);
const webauthnCredentialRepository: Repository<WebauthnCredentialEntity> = AppDataSource.getRepository(WebauthnCredentialEntity);


async function createUser(createUser: CreateUser, isAdmin: boolean = false): Promise<Result<UserEntity, CreateUserErr>> {
	try {
		const uuid = "uuid" in createUser ? createUser.uuid : UserId.generate();
		const user = await userRepository.save(userRepository.create({
			...createUser,
			uuid,
			did: uuid.id,
			isAdmin,
		}));
		const fcmTokenEntity = new FcmTokenEntity();
		fcmTokenEntity.value = createUser.fcmToken;
		fcmTokenEntity.user = user;
		AppDataSource.getRepository(FcmTokenEntity).save(fcmTokenEntity);

		return Ok(user);
	}
	catch(e) {
		console.log(e);
		return Err(CreateUserErr.ALREADY_EXISTS);
	}
}

async function getUser(id: UserId): Promise<Result<UserEntity, GetUserErr>> {
	try {
		const res = await userRepository.findOne({ where: { uuid: Equal(id) } });
		if (!res) {
			return Err(GetUserErr.NOT_EXISTS);
		}
		return Ok(res);
	}
	catch(e) {
		console.log(e);
		return Err(GetUserErr.NOT_EXISTS);
	}
}

async function deleteUser(id: UserId, options?: { entityManager: EntityManager }): Promise<Result<{}, DeleteUserErr>> {
	try {
		return await (options?.entityManager || userRepository.manager).transaction(async (manager) => {
			const user = await manager.findOne(UserEntity, { where: { uuid: Equal(id) }});
			await manager.delete(WebauthnCredentialEntity, { user });
			await manager.delete(UserEntity, { uuid: id });
			return Ok({})
		});
	}
	catch(e) {
		console.log(e);
		return Err(DeleteUserErr.FAILED_TO_DELETE);
	}
}

async function getUserByCredentials(username: string, password: string): Promise<Result<UserEntity, GetUserErr>> {
	try {
		return await userRepository.manager.transaction(async (manager) => {
			const user = await manager.findOne(UserEntity, { where: { username } });
			if (user && user.passwordHash) {
				const scryptRes = await scrypt.verifyHash(password, user.passwordHash);
				if (scryptRes.ok) {
					if (scryptRes.val) {
						return Ok(user);
					} else {
						return Err(GetUserErr.NOT_EXISTS);
					}

				} else {
					// User isn't migrated to scrypt yet - fall back to sha256
					const sha256Hash = crypto.createHash('sha256').update(password).digest('base64');

					if (user.passwordHash === sha256Hash) {
						// Upgrade the user to scrypt
						user.passwordHash = await scrypt.createHash(password);
						await manager.save(user);

						return Ok(user);
					} else {
						return Err(GetUserErr.NOT_EXISTS);
					}
				}

			} else {
				// Compute a throwaway hash anyway so we don't leak timing information
				await scrypt.createHash(password);
				return Err(GetUserErr.NOT_EXISTS);
			}
		});
	} catch (e) {
		console.log(e);
		return Err(GetUserErr.DB_ERR)
	}
}


async function getUserByWebauthnCredential(userId: UserId, credentialId: Buffer): Promise<Result<[UserEntity, WebauthnCredentialEntity], GetUserErr>> {
	try {
		console.log("getUserByWebauthnCredential", userId, base64url.encode(credentialId));
		const q = userRepository.createQueryBuilder("user")
			.leftJoinAndSelect("user.webauthnCredentials", "credential")
			.where("user.uuid = :uuid", { uuid: userId.id })
			.andWhere("credential.credentialId = :credentialId", { credentialId });
		console.log(q.getSql());
		const userRes = await q.getOne();
		console.log(userRes);
		if (!userRes) {
			return Err(GetUserErr.NOT_EXISTS);
		}
		if (userRes.webauthnCredentials.length !== 1) {
			return Err(GetUserErr.NOT_EXISTS);
		} else {
			return Ok([userRes, userRes.webauthnCredentials[0]]);
		}
	}
	catch(e) {
		console.log(e);
		return Err(GetUserErr.NOT_EXISTS);
	}
}

async function getAllUsers(): Promise<Result<UserEntity[], GetUserErr>> {
	try {

		let res = await AppDataSource.getRepository(UserEntity)
			.createQueryBuilder("user")
			.getMany();
		if (!res) {
			return Err(GetUserErr.NOT_EXISTS);
		}
		return Ok(res);
	}
	catch(e) {
		console.log(e);
		return Err(GetUserErr.DB_ERR)
	}
}

function newWebauthnCredentialEntity(data: DeepPartial<WebauthnCredentialEntity>, manager?: EntityManager): WebauthnCredentialEntity {
	const entity = (manager || webauthnCredentialRepository.manager).create(WebauthnCredentialEntity, data);
	entity.createTime = new Date();
	entity.lastUseTime = new Date();
	return entity;
}

async function updateUser<E = never>(id: UserId, update: (user: UserEntity, entityManager: EntityManager) => UserEntity | Result<UserEntity, E>): Promise<Result<UserEntity, UpdateUserErr | E>> {
	try {
		return await userRepository.manager.transaction(async (manager) => {
			const res = await manager.findOne(UserEntity, { where: { uuid: Equal(id) } });
			if (!res) {
				return Promise.reject(Err(UpdateUserErr.NOT_EXISTS));
			}

			const updatedUser = update(res, manager);
			if (isResult(updatedUser)) {
				if (updatedUser.ok) {
					await manager.save(updatedUser.val);
					return updatedUser;
				} else {
					return updatedUser;
				}
			} else {
				await manager.save(updatedUser);
				return Ok(updatedUser);
			}
		});
	} catch (e) {
		if (isResult(e)) {
			if (e.err) {
				return e as Result<UserEntity, UpdateUserErr | E>;
			}
		} else {
			console.log(e);
			return Err(UpdateUserErr.DB_ERR);
		}
	}
}

async function updateWebauthnCredentialWithManager(
	credential: WebauthnCredentialEntity,
	update: (credential: WebauthnCredentialEntity, manager: EntityManager) => WebauthnCredentialEntity,
	manager: EntityManager,
): Promise<Result<WebauthnCredentialEntity, UpdateUserErr>> {
	try {
		const updated = update(credential, manager);
		const res = await manager.save(updated);
		return Ok(res);
	} catch (e) {
		console.log(e);
		return Err(UpdateUserErr.DB_ERR);
	}
}

async function updateWebauthnCredential(
	credential: WebauthnCredentialEntity,
	update: (credential: WebauthnCredentialEntity, manager: EntityManager) => WebauthnCredentialEntity,
): Promise<Result<WebauthnCredentialEntity, UpdateUserErr>> {
	return await userRepository.manager.transaction(async (manager) => {
		return await updateWebauthnCredentialWithManager(credential, update, manager);
	});
}

async function updateWebauthnCredentialById(userId: UserId, credentialUuid: string, update: (credential: WebauthnCredentialEntity, manager: EntityManager) => WebauthnCredentialEntity): Promise<Result<WebauthnCredentialEntity, UpdateUserErr>> {
	console.log("updateWebauthnCredentialById", userId, credentialUuid);
	return await webauthnCredentialRepository.manager.transaction(async (manager) => {
		const q = userRepository.createQueryBuilder("user")
			.leftJoinAndSelect("user.webauthnCredentials", "credential")
			.where("user.uuid = :uuid", { uuid: userId.id })
			.andWhere("credential.id = :credentialUuid", { credentialUuid });
		console.log("q", q.getQueryAndParameters());
		const userRes = await q.getOne();
		console.log(userRes);

		return updateWebauthnCredentialWithManager(userRes.webauthnCredentials[0], update, manager);
	});
}

async function deleteWebauthnCredential(user: UserEntity, credentialUuid: string, updatePrivateData: EtagUpdate<Buffer>): Promise<Result<void, UpdateUserErr>> {
	try {
		return Ok(await runTransaction(async (manager) => {
			const userRes = await manager.findOne(UserEntity, { where: { uuid: Equal(user.uuid) }});
			if (!userRes) {
				return Err(UpdateUserErr.NOT_EXISTS);
			}

			const numCredentials = await manager.createQueryBuilder()
				.select()
				.from(WebauthnCredentialEntity, "cred")
				.where({ user })
				.getCount();
			if (numCredentials < 2) {
				return Err(UpdateUserErr.LAST_WEBAUTHN_CREDENTIAL);
			}

			const res = await manager.createQueryBuilder()
				.delete()
				.from(WebauthnCredentialEntity)
				.where({ user, id: credentialUuid })
				.execute();
			if (res.affected > 0) {
				const newPrivateData = checkedUpdate(
					updatePrivateData.expectTag,
					privateDataEtag,
					{
						currentValue: userRes.privateData,
						newValue: updatePrivateData.newValue,
					});
				if (newPrivateData.ok) {
					await manager.update(UserEntity, { uuid: user.uuid }, { privateData: newPrivateData.val });
					return Ok.EMPTY;
				} else {
					return Err(UpdateUserErr.PRIVATE_DATA_CONFLICT);
				}
			} else if (res.affected === 0) {
				return Err(UpdateUserErr.NOT_EXISTS);
			}
		}));

	} catch (e) {
		console.log('Failed to delete WebAuthn credential:', e);
		return Err(e);
	}
}

export {
	UserEntity,
	WebauthnCredentialEntity,
	CreateUser,
	GetUserErr,
	UpdateUserErr,
	createUser,
	getUser,
	getUserByCredentials,
	UpdateFcmError,
	getUserByWebauthnCredential,
	getAllUsers,
	newWebauthnCredentialEntity,
	updateUser,
	deleteWebauthnCredential,
	updateWebauthnCredential,
	updateWebauthnCredentialById,
	deleteUser,
}
