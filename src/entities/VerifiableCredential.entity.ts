import { Err, Ok, Result } from "ts-results";
import { Entity, EntityManager, PrimaryGeneratedColumn, Column, Repository} from "typeorm"
import AppDataSource from "../AppDataSource";
import { VerifiableCredentialFormat } from "../types/oid4vci";
import { deletePresentationsByCredentialId } from './VerifiablePresentation.entity';


@Entity({ name: "verifiable_credential" })
export class VerifiableCredentialEntity {
	@PrimaryGeneratedColumn()
	id: number = -1;

	// @Column({ unique: true })
	// identifier: string = "";

	// @Column({ type: 'blob', nullable: false })
	// jwt: string = "";

	@Column({ nullable: false })
	holderDID: string = "";


	@Column({ nullable: false })
	credentialIdentifier: string = ""; // for JWTs it is the "jti" attribute

	@Column({ nullable:false, type: 'blob' })
	credential: Buffer = Buffer.from("");


	@Column({ nullable: false })
	issuerDID: string = ""

	@Column({ nullable: false })
	issuerURL: string = "";

	@Column()
	issuerFriendlyName: string = "";

	@Column({ nullable: false })
	format: string; // = CredentialTypes.JWT_VC; // 'ldp_vc' or 'jwt_vc' or "vc+sd-jwt"


	@Column({ nullable: false })
	logoURL: string = "";

	@Column({ nullable: false })
	backgroundColor: string = "";


	@Column({ type: "datetime", nullable: false })
	issuanceDate: Date = new Date();
}


const verifiableCredentialRepository: Repository<VerifiableCredentialEntity> = AppDataSource.getRepository(VerifiableCredentialEntity);

enum GetVerifiableCredentialsErr {
	DB_ERR = "DB_ERR"
}

enum CreateVerifiableCredentialErr {
	DB_ERR = "DB_ERR"
}
enum DeleteVerifiableCredentialErr {
	DB_ERR = "DB_ERR",
	CREDENTIAL_NOT_FOUND = "CREDENTIAL_NOT_FOUND"
}

type VerifiableCredential = {
	id?: number;
	holderDID: string;
	credentialIdentifier: string;
	credential: string;
	issuerDID: string;
	issuerURL: string;
	format: VerifiableCredentialFormat;
	logoURL: string;
	backgroundColor: string;
	issuanceDate: Date;
	issuerFriendlyName: string;
}


async function createVerifiableCredential(createVc: VerifiableCredential) {
	try {
		console.log("Storing VC...")
		let vc = {
			...createVc,
		};
		const res = await AppDataSource
			.createQueryBuilder()
			.insert()
			.into(VerifiableCredentialEntity).values([
				{...vc, credential: Buffer.from(vc.credential) }
			])
			.execute();
		return Ok({});
	}
	catch(e) {
		console.log(e);
		return Err(CreateVerifiableCredentialErr.DB_ERR);
	}
}

async function deleteVerifiableCredential(holderDID:string, credentialId: string) {
	try {
		console.log("Deleting VPs containing the VC", credentialId);
		await deletePresentationsByCredentialId(holderDID, credentialId);
		console.log("Deleting VC...");

		const res = await AppDataSource
			.createQueryBuilder()
			.delete()
			.from(VerifiableCredentialEntity)
			.where("credentialIdentifier = :credentialId", { credentialId })
			.execute();

		// Check if any rows were affected to determine if the deletion was successful
		if (res.affected && res.affected > 0) {
			console.log("The VC was successfully deleted")
			return Ok({});
		} else {
			return Err(DeleteVerifiableCredentialErr.CREDENTIAL_NOT_FOUND);
		}
	} catch (e) {
		console.log(e);
		return Err(DeleteVerifiableCredentialErr.DB_ERR);
	}
}

async function getAllVerifiableCredentials(holderDID: string): Promise<Result<VerifiableCredential[], GetVerifiableCredentialsErr>> {
	try {
		const vcList = await verifiableCredentialRepository
			.createQueryBuilder("vc")
			.where("vc.holderDID = :did", { did: holderDID })
			.getMany();

		// convert all Blobs to string
		const decodedVcList = vcList.map((vc) => {
			const transformed = {
				...vc,
				credential: vc.credential.toString(),
			}
			return transformed as VerifiableCredential;
		})
		return Ok(decodedVcList);
	}
	catch(e) {
		console.log(e);
		return Err(GetVerifiableCredentialsErr.DB_ERR);
	}
}


async function getVerifiableCredentialByCredentialIdentifier(holderDID: string, credentialId: string): Promise<Result<VerifiableCredential, GetVerifiableCredentialsErr>> {
	try {
		const vc = await verifiableCredentialRepository
			.createQueryBuilder("vc")
			.where("vc.holderDID = :did and vc.credentialIdentifier = :cid", { did: holderDID, cid: credentialId })
			.getOne();

		// convert all Blobs to string
		const transformed = {
			...vc,
			credential: vc.credential.toString(),
		}
		return Ok(transformed as VerifiableCredential);
	}
	catch(e) {
		console.log(e);
		return Err(GetVerifiableCredentialsErr.DB_ERR);
	}
}

async function deleteAllCredentialsWithHolderDID(holderDID: string, options?: { entityManager: EntityManager }): Promise<Result<{}, DeleteVerifiableCredentialErr>> {
	try {
		return await (options?.entityManager || verifiableCredentialRepository.manager).transaction(async (manager) => {
			await manager
				.createQueryBuilder()
				.from(VerifiableCredentialEntity, "vc")
				.delete()
				.where("holderDID = :did", { did: holderDID })
				.execute();
			return Ok({});
		});
	}
	catch(e) {
		console.log(e);
		return Err(DeleteVerifiableCredentialErr.DB_ERR);
	}
}

export {
	GetVerifiableCredentialsErr,
	VerifiableCredential,
	CreateVerifiableCredentialErr,
	DeleteVerifiableCredentialErr,
	getAllVerifiableCredentials,
	createVerifiableCredential,
	deleteVerifiableCredential,
	getVerifiableCredentialByCredentialIdentifier,
	deleteAllCredentialsWithHolderDID
}
