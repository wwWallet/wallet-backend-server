import { Err, Ok, Result } from "ts-results";
import { Entity, PrimaryGeneratedColumn, Column, Repository} from "typeorm"
import AppDataSource from "../AppDataSource";
import { VerifiableCredentialFormat } from "../types/oid4vci";



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
	format: string; // = CredentialTypes.JWT_VC; // 'ldp_vc' or 'jwt_vc'


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


export {
	GetVerifiableCredentialsErr,
	VerifiableCredential,
	CreateVerifiableCredentialErr,
	getAllVerifiableCredentials,
	createVerifiableCredential,
	getVerifiableCredentialByCredentialIdentifier
}