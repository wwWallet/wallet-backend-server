import { Err, Ok, Result } from "ts-results";
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany, Repository, Generated, EntityManager, DeepPartial } from "typeorm"
import crypto from "node:crypto";

import AppDataSource from "../AppDataSource";
import * as scrypt from "../scrypt";


@Entity({ name: "user" })
class UserEntity {
	@PrimaryGeneratedColumn()
	id: number = -1;


	@Column({ unique: true, nullable: false})
	username: string = "";

	@Column({ unique: true, nullable: false })
	did: string = "";

	@Column({ nullable: false })
	passwordHash: string = "";


	@Column({ type: 'blob', nullable: false })
	keys: Buffer = Buffer.from("");


	// Explicit default to workaround a bug in typeorm: https://github.com/typeorm/typeorm/issues/3076#issuecomment-703128687
	@Column({ type: "blob", nullable: true, default: () => "NULL" })
	fcmToken: Buffer;

	// Explicit default to workaround a bug in typeorm: https://github.com/typeorm/typeorm/issues/3076#issuecomment-703128687
	@Column({ type: "blob", nullable: true, default: () => "NULL" })
	browserFcmToken: Buffer;

	@Column({ type: "bool", default: false })
	isAdmin: boolean = false;

	@Column({ nullable: false })
	@Generated("uuid")
	webauthnUserHandle: string;

	@OneToMany(() => WebauthnCredentialEntity, (credential) => credential.user, { cascade: true, eager: true, nullable: false })
	webauthnCredentials: WebauthnCredentialEntity[];
}

@Entity({ name: "webauthn_credential" })
class WebauthnCredentialEntity {
	@PrimaryGeneratedColumn("uuid")
	id: string;

	@ManyToOne(() => UserEntity, (user) => user.webauthnCredentials, { nullable: false })
	user: UserEntity;

	@Column({ nullable: false })
	credentialId: Buffer;

	@Column({ nullable: false })
	userHandle: Buffer;

	// Explicit default to workaround a bug in typeorm: https://github.com/typeorm/typeorm/issues/3076#issuecomment-703128687
	@Column({ nullable: true, default: () => "NULL" })
	nickname: string;

	@Column({ type: "datetime", nullable: false })
	createTime: Date;

	@Column({ type: "datetime", nullable: false })
	lastUseTime: Date;

	@Column({ nullable: false })
	publicKeyCose: Buffer;

	@Column({ nullable: false })
	signatureCount: number = 0;

	@Column("simple-json", { nullable: false })
	transports: string[];

	@Column({ nullable: false })
	attestationObject: Buffer;

	@Column({ nullable: false })
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
	did: string;
	passwordHash: string;
	keys: Buffer;
	fcmToken: Buffer;
	browserFcmToken: Buffer;
	webauthnUserHandle: string;
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
	DB_ERR = "DB_ERR"
}

enum UpdateFcmError {
	DB_ERR = "Failed to update FCM token list"
}


const userRepository: Repository<UserEntity> = AppDataSource.getRepository(UserEntity);
const webauthnCredentialRepository: Repository<WebauthnCredentialEntity> = AppDataSource.getRepository(WebauthnCredentialEntity);


async function createUser(createUser: CreateUser, isAdmin: boolean = false): Promise<Result<{}, CreateUserErr>> {
	try {
		const res = await AppDataSource
			.createQueryBuilder()
			.insert()
			.into(UserEntity).values([
				{ 
					...createUser,
					isAdmin: isAdmin
				}
			])
			.execute();

		return Ok({});
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

async function getUserByCredentials(username: string, password: string): Promise<Result<UserEntity, GetUserErr>> {
	try {
		return await userRepository.manager.transaction(async (manager) => {
			const user = await manager.findOne(UserEntity, { where: { username } });
			if (user) {
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
		const q = userRepository.createQueryBuilder("user")
			.leftJoinAndSelect("user.webauthnCredentials", "credential")
			.where("user.webauthnUserHandle = :userHandle", { userHandle })
			.andWhere("credential.credentialId = :credentialId", { credentialId });
		console.log(q.getSql());
		const userRes = await q.getOne();
		if (!userRes) {
			return Err(GetUserErr.NOT_EXISTS);
		}
		console.log(userRes);
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

async function updateUserByDID(did: string, update: (user: UserEntity, entityManager: EntityManager) => UserEntity): Promise<Result<UserEntity, UpdateUserErr>> {
	return await userRepository.manager.transaction(async (manager) => {
		const res = await manager.findOne(UserEntity, {
			where: {
				did: did
			}
		});
		if (!res) {
			return Err(UpdateUserErr.NOT_EXISTS);
		}

		const updatedUser = update(res, manager);

		try {
			await manager.save(updatedUser);
			return Ok(res);
		} catch (e) {
			console.log(e);
			return Err(UpdateUserErr.DB_ERR);
		}
	});
}

async function updateWebauthnCredential(credential: WebauthnCredentialEntity, update: (credential: WebauthnCredentialEntity) => WebauthnCredentialEntity): Promise<Result<WebauthnCredentialEntity, UpdateUserErr>> {
	try {
		const updated = update(credential);
		const res = await webauthnCredentialRepository.save(updated);
		return Ok(res);
	} catch (e) {
		console.log(e);
		return Err(UpdateUserErr.DB_ERR);
	}
}

async function deleteWebauthnCredential(user: UserEntity, credentialUuid: string): Promise<Result<{}, UpdateUserErr>> {
	try {
		const res = await webauthnCredentialRepository.createQueryBuilder()
			.delete()
			.from(WebauthnCredentialEntity)
			.where({ user, id: credentialUuid })
			.execute();
		if (res.affected > 0) {
			return Ok({});
		} else if (res.affected === 0) {
			return Err(UpdateUserErr.NOT_EXISTS);
		}
	} catch (e) {
		console.log(e);
		return Err(UpdateUserErr.DB_ERR);
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
}
