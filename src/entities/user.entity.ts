import { Err, Ok, Result } from "ts-results";
import { Entity, PrimaryGeneratedColumn, Column, Repository} from "typeorm"
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


	@Column( {type: "blob", nullable: true })
	fcmToken: Buffer = Buffer.from("");

	@Column( { type: "blob", nullable: true })
	browserFcmToken: Buffer = Buffer.from("");

	@Column({ type: "bool", default: false })
	isAdmin: boolean = false;

	@Column({ nullable: false })
	pbkdf2Params: string;

	@Column({ type: "blob", nullable: false })
	privateData: Buffer;
}


type CreateUser = {
	username: string;
	did: string;
	passwordHash: string;
	keys: Buffer;
	fcmToken: Buffer;
	browserFcmToken: Buffer;
	pbkdf2Params: string;
	privateData: Buffer;
}


enum CreateUserErr {
	ALREADY_EXISTS = "ALREADY_EXISTS"
}

enum GetUserErr {
	NOT_EXISTS = "NOT_EXISTS",
	DB_ERR = "DB_ERR"
}

enum UpdateFcmError {
	DB_ERR = "Failed to update FCM token list"
}


const userRepository: Repository<UserEntity> = AppDataSource.getRepository(UserEntity);


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

async function getUserByUsername(username: string): Promise<Result<UserEntity, GetUserErr>> {
	try {

		const res = await AppDataSource.getRepository(UserEntity)
			.createQueryBuilder("user")
			.where("user.username = :username", { username: username })
			.getOne();
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

export {
	UserEntity,
	CreateUser,
	GetUserErr,
	createUser,
	getUserByDID,
	getUserByCredentials,
	UpdateFcmError,
	getUserByUsername,
	getAllUsers
}
