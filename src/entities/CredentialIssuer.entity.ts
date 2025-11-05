import { Err, Ok, Result } from "ts-results";
import { Column, Entity, PrimaryGeneratedColumn, Repository } from "typeorm";
import AppDataSource from "../AppDataSource";


@Entity({ name: "credential_issuer" })
class CredentialIssuerEntity {
	@PrimaryGeneratedColumn()
	id: number = -1;

	@Column({ type: "varchar", nullable: false })
	credentialIssuerIdentifier: string = "";

	// Explicit default to workaround a bug in typeorm: https://github.com/typeorm/typeorm/issues/3076#issuecomment-703128687
	@Column({ nullable: true, type: "varchar", default: () => "NULL" })
	clientId?: string;


	// Explicit default to workaround a bug in typeorm: https://github.com/typeorm/typeorm/issues/3076#issuecomment-703128687
	@Column({ nullable: true, type: "tinyint", default: () => "NULL" })
	visible: boolean;
}

enum GetLegalPersonErr {
	NOT_EXISTS = "NOT_EXISTS",
	DB_ERR = "DB_ERR"
}

const credentialIssuerRepository: Repository<CredentialIssuerEntity> = AppDataSource.getRepository(CredentialIssuerEntity);


async function getAllCredentialIssuers(): Promise<Result<CredentialIssuerEntity[], GetLegalPersonErr>> {
	try {
		const issuers = await credentialIssuerRepository.createQueryBuilder()
			.getMany();
		return Ok(issuers);
	}
	catch(e) {
		console.log(e);
		return Err(GetLegalPersonErr.DB_ERR);
	}
}

export {
	CredentialIssuerEntity,
	getAllCredentialIssuers,
}
