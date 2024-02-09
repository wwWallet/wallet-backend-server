import { Column, Entity, ManyToOne, PrimaryGeneratedColumn, Repository } from "typeorm";
import { UserEntity } from "./user.entity";
import AppDataSource from "../AppDataSource";

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

async function deleteAllFcmTokensForUser(did: string) {
	const tokens = await fcmTokenRepository.find({ where: { user: { did: did } } });
	await fcmTokenRepository.remove(tokens);
}

export {
	deleteAllFcmTokensForUser
}