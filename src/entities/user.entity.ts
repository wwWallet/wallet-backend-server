import { Err, Ok, Result } from "ts-results";
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany, Repository, Generated, EntityManager, DeepPartial, JoinColumn } from "typeorm"
import crypto from "node:crypto";
import base64url from "base64url";

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


@Entity({ name: "user" })
class UserEntity {
	@PrimaryGeneratedColumn()
	id: number;


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

	@Column({ nullable: false, update: false })
	@Generated("uuid")
	webauthnUserHandle: string;


	@Column({ type: "enum" ,enum: WalletType, default: WalletType.DB })
	walletType: WalletType;

	@OneToMany(
		() => WebauthnCredentialEntity, (credential) => credential.user,
		{ cascade: true, onDelete: "CASCADE", orphanedRowAction: "delete", eager: true, nullable: false })
	webauthnCredentials: WebauthnCredentialEntity[];


	@OneToMany(() => FcmTokenEntity, (fcmToken) => fcmToken.user, { eager: true })
	fcmTokenList: FcmTokenEntity[];
}

@Entity({ name: "webauthn_credential" })
class WebauthnCredentialEntity {
	@PrimaryGeneratedColumn("uuid")
	id: string;

	@ManyToOne(() => UserEntity, (user) => user.webauthnCredentials, { nullable: false })
	user: UserEntity;

	@Column({ nullable: false, update: false })
	credentialId: Buffer;

	@Column({ nullable: false, update: false })
	userHandle: Buffer;

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
	did: string;
	passwordHash: string;
	fcmToken: string;
	privateData: Buffer;
	webauthnUserHandle: string;
} | {
	displayName: string,
	did: string;
	keys: Buffer;
	fcmToken: string;
	privateData: Buffer;
	webauthnUserHandle: string;
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
		const user = await userRepository.save(userRepository.create({
			...createUser,
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

async function getUserByDID(did: string): Promise<Result<UserEntity, GetUserErr>> {
	try {
		const res = await userRepository.findOne({
			where: {
				did: did
			}
		});
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

async function deleteUserByDID(did: string, options?: { entityManager: EntityManager }): Promise<Result<{}, DeleteUserErr>> {
	try {
		return await (options?.entityManager || userRepository.manager).transaction(async (manager) => {
			const userRes = await manager.findOne(UserEntity, { where: { did: did }});

			await manager.delete(WebauthnCredentialEntity, {
				user: { id: userRes.id }
			});

			await manager.delete(UserEntity, {
				did: did
			});

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


async function getUserByWebauthnCredential(userHandle: string, credentialId: Buffer): Promise<Result<[UserEntity, WebauthnCredentialEntity], GetUserErr>> {
	try {
		console.log("getUserByWebauthnCredential", userHandle, base64url.encode(credentialId));
		const q = userRepository.createQueryBuilder("user")
			.leftJoinAndSelect("user.webauthnCredentials", "credential")
			.where("user.webauthnUserHandle = :userHandle", { userHandle })
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
// async function addFcmTokenByDID(did: string, newFcmToken: string) {
// 	try {
// 		const res = await AppDataSource.getRepository(UserEntity)
// 			.createQueryBuilder("user")
// 			.where("user.did = :did", { did: did })
// 			.getOne();
// 		const fcmTokens: string[] = JSON.parse(res.fcmTokens.toString());
// 		fcmTokens.push(newFcmToken);
// 		const updateRes = await AppDataSource.getRepository(UserEntity)
// 			.createQueryBuilder("user")
// 			.update({ fcmTokens: JSON.stringify(fcmTokens) })
// 			.where("did = :did", { did: did })
// 			.execute();
// 	}
// 	catch(err) {
// 		console.log(err);
// 		return Err(UpdateFcmError.DB_ERR);
// 	}
// }

function newWebauthnCredentialEntity(data: DeepPartial<WebauthnCredentialEntity>, manager?: EntityManager): WebauthnCredentialEntity {
	const entity = (manager || webauthnCredentialRepository.manager).create(WebauthnCredentialEntity, data);
	entity.createTime = new Date();
	entity.lastUseTime = new Date();
	return entity;
}

async function updateUserByDID<E = never>(did: string, update: (user: UserEntity, entityManager: EntityManager) => UserEntity | Result<UserEntity, E>): Promise<Result<UserEntity, UpdateUserErr | E>> {
	try {
		return await userRepository.manager.transaction(async (manager) => {
			const res = await manager.findOne(UserEntity, {
				where: {
					did: did
				}
			});
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

async function updateWebauthnCredentialById(userDid: string, credentialUuid: string, update: (credential: WebauthnCredentialEntity, manager: EntityManager) => WebauthnCredentialEntity): Promise<Result<WebauthnCredentialEntity, UpdateUserErr>> {
	console.log("updateWebauthnCredentialById", userDid, credentialUuid);
	return await webauthnCredentialRepository.manager.transaction(async (manager) => {
		const q = userRepository.createQueryBuilder("user")
			.leftJoinAndSelect("user.webauthnCredentials", "credential")
			.where("user.did = :userDid", { userDid })
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
			const userRes = await manager.findOne(UserEntity, { where: { did: user.did }});
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
					await manager.update(UserEntity, { did: user.did }, { privateData: newPrivateData.val });
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
	getUserByDID,
	getUserByCredentials,
	UpdateFcmError,
	getUserByWebauthnCredential,
	getAllUsers,
	newWebauthnCredentialEntity,
	updateUserByDID,
	deleteWebauthnCredential,
	updateWebauthnCredential,
	updateWebauthnCredentialById,
	deleteUserByDID
}
