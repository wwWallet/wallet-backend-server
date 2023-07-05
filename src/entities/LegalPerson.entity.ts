import axios from "axios";
import { Err, Ok, Result } from "ts-results";
import { Column, Entity, PrimaryGeneratedColumn, Repository } from "typeorm";
import AppDataSource from "../AppDataSource";


@Entity({ name: "legal_person" })
class LegalPersonEntity {
  @PrimaryGeneratedColumn()
  id: number = -1;


	@Column({ nullable: false })
	friendlyName: string = "";

	@Column({ nullable: false })
	url: string = "";

	@Column({ nullable: false })
	did: string = "";


	@Column({ nullable: true })
	client_id: string = "";
	
	@Column({ nullable: true })
	client_secret: string = "";
}

type CreateLegalPerson = {
	username: string;
	did: string;
	passwordHash: string;
	keys: string;
	client_id: string;
	client_secret: string;
}


enum CreateLegalPersonErr {
	ALREADY_EXISTS = "ALREADY_EXISTS"
}

enum GetLegalPersonErr {
	NOT_EXISTS = "NOT_EXISTS",
	DB_ERR = "DB_ERR"
}

const legalPersonRepository: Repository<LegalPersonEntity> = AppDataSource.getRepository(LegalPersonEntity);





async function createIssuer(createIssuer: CreateLegalPerson) {
	try {
		console.log("Storing Issuer...")
		const res = await AppDataSource
			.createQueryBuilder()
			.insert()
			.into(LegalPersonEntity).values([
				{ ...createIssuer }
			])
			.execute();
		return Ok({});
	}
	catch(e) {
		console.log(e);
		return Err(CreateLegalPersonErr.ALREADY_EXISTS);
	}
}


async function getAllLegalPersons(): Promise<Result<LegalPersonEntity[], GetLegalPersonErr>> {
	try {
		const vcList = await legalPersonRepository 
			.createQueryBuilder("legal_person")
			.getMany();

		// convert all Blobs to actual data
		const decodedIssuers = vcList.map((issuer) => {
			return issuer as LegalPersonEntity;
		})
		return Ok(decodedIssuers);
	}
	catch(e) {
		console.log(e);
		return Err(GetLegalPersonErr.DB_ERR);
	}
}

async function getAllLegalPersonsDIDs(): Promise<Result<string[], GetLegalPersonErr>> {
	try {
		const vcList = await legalPersonRepository 
			.createQueryBuilder("legal_person")
			.getMany();

		// convert all Blobs to actual data
		const didList = vcList.map((issuer) => {
			return issuer.did
		})
		return Ok(didList);
	}
	catch(e) {
		console.log(e);
		return Err(GetLegalPersonErr.DB_ERR);
	}
}

async function getLegalPersonsBySearchParams(friendlyNameSubstring: string): Promise<Result<LegalPersonEntity[], GetLegalPersonErr>> {
	try {
		const issuersList = await legalPersonRepository 
			.createQueryBuilder("legal_person")
			.where("friendlyName LIKE '%:friendlyNameSubstring%", { friendlyNameSubstring })
			.getMany();

		// convert all Blobs to actual data
		const decodedIssuers = issuersList.map((issuer) => {
			return issuer as LegalPersonEntity;
		})
		return Ok(decodedIssuers);
	}
	catch(e) {
		console.log(e);
		return Err(GetLegalPersonErr.DB_ERR);
	}
}

/**
 * Will also update the issuer DB entity with the latest metadata
 * @param id 
 * @returns 
 */
async function getLegalPersonById(id: number): Promise<Result<LegalPersonEntity, GetLegalPersonErr>> {

	try {
		const issuer = await legalPersonRepository
			.createQueryBuilder("legal_person")
			.where("id = :id", { id })
			.getOne();

		return Ok(issuer);
	}
	catch(e) {
		return Err(GetLegalPersonErr.DB_ERR);
	}

}

/**
 * Will also update the issuer DB entity with the latest metadata
 * @param id 
 * @returns 
 */
async function getLegalPersonByDID(did: string): Promise<Result<LegalPersonEntity | null, GetLegalPersonErr>> {

	try {
		const issuer = await legalPersonRepository
			.createQueryBuilder("legal_person")
			.where("did = :did", { did })
			.getOne();
		return Ok(issuer);
	}
	catch(e) {
		return Err(GetLegalPersonErr.DB_ERR);
	}

}



/**
 * Will also update the issuer DB entity with the latest metadata
 * @param id 
 * @returns 
 */
async function getLegalPersonByUrl(url: string): Promise<Result<LegalPersonEntity | null, GetLegalPersonErr>> {

	try {
		const issuer = await legalPersonRepository
			.createQueryBuilder("legal_person")
			.where("url = :url", { url })
			.getOne();


		return Ok(issuer);
	}
	catch(e) {
		return Err(GetLegalPersonErr.DB_ERR);
	}

}

export {
	LegalPersonEntity,
	createIssuer,
	getAllLegalPersons,
	getLegalPersonsBySearchParams,
	getLegalPersonById,
	getLegalPersonByDID,
	getAllLegalPersonsDIDs,
	getLegalPersonByUrl
}