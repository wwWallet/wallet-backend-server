import { Column, Entity, EntityManager, ManyToOne, PrimaryGeneratedColumn, Repository } from "typeorm";
import { UserEntity } from "./user.entity";
import AppDataSource from "../AppDataSource";
import { Err, Ok, Result } from "ts-results";

@Entity({ name: "fcm_token" })
export class FcmTokenEntity {
	@PrimaryGeneratedColumn()
	id: number;

	@Column({ name: "value", type: "varchar", nullable: false })
	value: string;
	
	@ManyToOne(() => UserEntity, (user) => user.fcmTokenList)
	user: UserEntity;
}

const fcmTokenRepository: Repository<FcmTokenEntity> = AppDataSource.getRepository(FcmTokenEntity);

enum DeleteFcmTokenErr {
	DB_ERR = "DB_ERR"
}
async function deleteAllFcmTokensForUser(did: string, options?: { entityManager?: EntityManager }): Promise<Result<{}, DeleteFcmTokenErr>> {
	try {
		return await (options?.entityManager || fcmTokenRepository.manager).transaction(async (manager) => {
			const tokens = await manager.find(FcmTokenEntity, { where: { user: { did: did } } });
			await manager.remove(tokens);
			return Ok({});
		});
	}
	catch(e) {
		console.log(e);
		return Err(DeleteFcmTokenErr.DB_ERR);
	}
}

export {
	deleteAllFcmTokensForUser
}