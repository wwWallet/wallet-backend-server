import { Result, Ok, Err } from "ts-results";
import { Column, Entity, PrimaryGeneratedColumn, Repository } from "typeorm";
import AppDataSource from "../AppDataSource";

interface CredentialPortalDisplayLogo {
	uri: string;
	alt_text?: string;
	[key: string]: unknown;
}

interface CredentialPortalDisplay {
	name?: string;
	description?: string;
	locale?: string;
	logo?: CredentialPortalDisplayLogo;
	[key: string]: unknown;
}

@Entity({ name: "credential_portal" })
class CredentialPortalEntity {
	@PrimaryGeneratedColumn()
	id: number = -1;

	@Column({ type: "varchar", nullable: false })
	url: string = "";

	@Column({ type: "json", nullable: true, default: () => "NULL" })
	display?: CredentialPortalDisplay[];

	@Column({ type: "tinyint", default: 1 })
	visible: boolean;
}

const credentialPortalRepository: Repository<CredentialPortalEntity> = AppDataSource.getRepository(CredentialPortalEntity);

async function getAllCredentialPortals(): Promise<Result<CredentialPortalEntity[], "DB_ERR">> {
	try {
		const portals = await credentialPortalRepository.createQueryBuilder()
			.getMany();
		return Ok(portals);
	}
	catch(e) {
		console.log(e);
		return Err("DB_ERR");
	}
}

export {
	CredentialPortalEntity,
	getAllCredentialPortals,
}
