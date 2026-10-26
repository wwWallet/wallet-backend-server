import { Err, Ok, Result } from "ts-results";
import { Column, Entity, PrimaryGeneratedColumn, Repository } from "typeorm";
import AppDataSource from "../AppDataSource";
import { logger } from "../logger";

const log = logger.child({ module: "TrustedRootCertificate" });


@Entity({ name: "trusted_root_certificate" })
class TrustedRootCertificateEntity {
	@PrimaryGeneratedColumn()
	id: number = -1;

	@Column({ type: "blob", nullable: false })
	certificate: string = "";
}

enum GetTrustedRootCertErr {
	NOT_EXISTS = "NOT_EXISTS",
	DB_ERR = "DB_ERR"
}

const trustedRootCertificateRepository: Repository<TrustedRootCertificateEntity> = AppDataSource.getRepository(TrustedRootCertificateEntity);


async function getAllTrustedRootCertificates(): Promise<Result<TrustedRootCertificateEntity[], GetTrustedRootCertErr>> {
	try {
		const certs = await trustedRootCertificateRepository.createQueryBuilder()
			.getMany();

		const result = certs.map((cert) => ({ ...cert, certificate: cert.certificate.toString() }));
		return Ok(result);
	}
	catch(e) {
		log.error({ err: e }, "Failed to get trusted root certificates");
		return Err(GetTrustedRootCertErr.DB_ERR);
	}
}

export {
	TrustedRootCertificateEntity,
	getAllTrustedRootCertificates,
}
