import { Err, Ok, Result } from "ts-results";
import { Entity, PrimaryGeneratedColumn, Column, Repository} from "typeorm"
import AppDataSource from "../AppDataSource";
import crypto from "node:crypto";
import base64url from "base64url";


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

	@Column({ type: "bool", default: false })
	isAdmin: boolean = false;
}


type CreateUser = {
	username: string;
	did: string;
	passwordHash: string;
	keys: Buffer;
	fcmToken: Buffer;
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

// Settings for new password hashes
// Best practice guidelines from https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
const scryptKeyLen: number = 64;
const scryptCost: number = 131072; // 2^17
const scryptBlockSize: number = 8;
const scryptMaxMem: number = 128 * scryptCost * scryptBlockSize * 2;

function parseScryptParams(passwordHash: string): Result<{ salt: Buffer, keyLen: number, cost: number, blockSize: number }, void> {
	try {
		if (!passwordHash.startsWith("$")) {
			return Err.EMPTY;
		}

		const splits = passwordHash.split('$');
		const keyLen = parseInt(splits[1], 10);
		const cost = parseInt(splits[2], 10);
		const blockSize = parseInt(splits[3], 10);
		const salt = base64url.toBuffer(splits[4]);
		return Ok({ salt, keyLen, cost, blockSize });

	} catch (e) {
		return Err.EMPTY;
	}
}

async function computeScrypt(password: string, salt: Buffer, keyLen: number, cost: number, blockSize: number): Promise<string> {
	return new Promise((resolve, reject) => {
		crypto.scrypt(
			Buffer.from(password, "utf8"),
			salt,
			keyLen,
			{ cost, blockSize, maxmem: scryptMaxMem },
			(err, derivedKey) => {
				if (err) {
					console.error("Failed to compute scrypt hash", err);
					reject(err);
				} else {
					const result = "$" + [keyLen, cost, blockSize, base64url.encode(salt), base64url.encode(derivedKey)].join("$");
					resolve(result);
				}
			},
		);
	});
}

async function createScryptHash(password: string): Promise<string> {
	return await computeScrypt(password, crypto.randomBytes(32), scryptKeyLen, scryptCost, scryptBlockSize);
}

/**
 * @return Ok(true) if password matches; Ok(false) if password is scrypt-hashed but does not match; Err(void) if password is not scrypt-hashed.
	*/
async function verifyScryptHash(password: string, scryptHash: string): Promise<Result<boolean, void>> {
	const decodeRes = parseScryptParams(scryptHash);
	if (decodeRes.ok) {
		const { salt, keyLen, cost, blockSize } = decodeRes.val;
		const encoded = await computeScrypt(password, salt, keyLen, cost, blockSize);
		return Ok(encoded === scryptHash);
	} else {
		return Err.EMPTY;
	}
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
					keys: createUser.keys,
					fcmToken: createUser.fcmToken,
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
				const scryptRes = await verifyScryptHash(password, user.passwordHash);
				if (scryptRes.ok) {
					if (scryptRes.val) {
						return Ok(user);
					} else {
						return Err(GetUserErr.NOT_EXISTS);
					}

				} else {
					// User isn't migrated to sha256 yet - fall back to sha256
					const sha256Hash = crypto.createHash('sha256').update(password).digest('base64');

					if (user.passwordHash === sha256Hash) {
						// Upgrade the user to scrypt
						user.passwordHash = await createScryptHash(password);
						await manager.save(user);

						return Ok(user);
					} else {
						return Err(GetUserErr.NOT_EXISTS);
					}
				}

			} else {
				// Compute a throwaway hash anyway so we don't leak timing information
				await createScryptHash(password);
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