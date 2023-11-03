import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { UserEntity } from "./user.entity";

@Entity({ name: "fcm_token" })
export class FcmTokenEntity {
	@PrimaryGeneratedColumn()
	id: number;

	@Column({ name: "value", type: "varchar", nullable: false })
	value: string;
	
	@ManyToOne(() => UserEntity, (user) => user.fcmTokenList)
	user: UserEntity;
}