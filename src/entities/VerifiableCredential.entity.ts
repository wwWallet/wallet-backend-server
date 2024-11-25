import { Err, Ok, Result } from "ts-results";
import { Entity, EntityManager, PrimaryGeneratedColumn, Column, Repository} from "typeorm"
import AppDataSource from "../AppDataSource";
import { VerifiableCredentialFormat } from "../types/oid4vci";
import { deletePresentationsByCredentialId } from './VerifiablePresentation.entity';
import { nullable } from "zod";


@Entity({ name: "verifiable_credential" })
export class VerifiableCredentialEntity {
	@PrimaryGeneratedColumn()
	id: number = -1;

	@Column({ nullable: false })
	holderDID: string = "";

	@Column({ nullable: false })
	credentialIdentifier: string = "";

	@Column({ nullable: false, type: 'blob' })
	credential: string;

	@Column({ type: "varchar", nullable: false })
	format: string;

	@Column({ type: "varchar", nullable: false, default: "" })
	credentialConfigurationId: string = "";

	@Column({ type: "varchar", nullable: false, default: "" })
	credentialIssuerIdentifier: string = "";

	@Column({ type: "smallint", nullable: false, default: 0 })
	instanceId: number = 0;

	@Column({ type: "smallint", nullable: false, default: 0 })
	sigCount: number = 0;
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



async function createVerifiableCredential(createVc: Partial<VerifiableCredentialEntity>) {
	try {
		console.log("Storing VC...")
		let vc = {
			...createVc,
		};
		const res = await AppDataSource
			.createQueryBuilder()
			.insert()
			.into(VerifiableCredentialEntity).values([
				{...vc }
			])
			.execute();
		return Ok({});
	}
	catch(e) {
		console.log(e);
		return Err(CreateVerifiableCredentialErr.DB_ERR);
	}
}


async function updateVerifiableCredential(credential: Partial<VerifiableCredentialEntity>) {
	try {
		console.log("Updating VC...")
		await AppDataSource
			.createQueryBuilder()
			.update(VerifiableCredentialEntity)
			.set({ ...credential })
			.where("credentialIdentifier = :cred_id and instanceId = :instance_id", { cred_id: credential.credentialIdentifier, instance_id: credential.instanceId })
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

async function getAllVerifiableCredentials(holderDID: string): Promise<Result<VerifiableCredentialEntity[], GetVerifiableCredentialsErr>> {
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
			return transformed as VerifiableCredentialEntity;
		})
		return Ok(decodedVcList);
	}
	catch(e) {
		console.log(e);
		return Err(GetVerifiableCredentialsErr.DB_ERR);
	}
}


async function getVerifiableCredentialByCredentialIdentifier(holderDID: string, credentialId: string): Promise<Result<VerifiableCredentialEntity, GetVerifiableCredentialsErr>> {
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
		return Ok(transformed as VerifiableCredentialEntity);
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
	CreateVerifiableCredentialErr,
	DeleteVerifiableCredentialErr,
	getAllVerifiableCredentials,
	createVerifiableCredential,
	updateVerifiableCredential,
	deleteVerifiableCredential,
	getVerifiableCredentialByCredentialIdentifier,
	deleteAllCredentialsWithHolderDID
}
