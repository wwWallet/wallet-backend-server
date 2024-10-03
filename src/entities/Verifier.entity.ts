import { Err, Ok, Result } from "ts-results";
import { Column, Entity, PrimaryGeneratedColumn, Repository } from "typeorm";
import AppDataSource from "../AppDataSource";


@Entity({ name: "verifier" })
class VerifierEntity {
	@PrimaryGeneratedColumn()
	id: number = -1;

	@Column({ type: "varchar", nullable: false })
	name: string = "";

	@Column({ type: "varchar", nullable: false })
	url: string = "";
}

export enum GetVerifierErr {
	DB_ERR
}

const verifierRepository: Repository<VerifierEntity> = AppDataSource.getRepository(VerifierEntity);


async function getAllVerifiers(): Promise<Result<VerifierEntity[], GetVerifierErr>> {
	try {
		const issuers = await verifierRepository.createQueryBuilder()
			.getMany();
		return Ok(issuers);
	}
	catch(e) {
		console.log(e);
		return Err(GetVerifierErr.DB_ERR);
	}
}

export {
	VerifierEntity,
	getAllVerifiers,
}
