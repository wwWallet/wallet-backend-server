import { MigrationInterface, QueryRunner } from "typeorm";

export class RemoveStorageTables1766402360554 implements MigrationInterface {

	public async up(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`DROP TABLE verifiable_credential`);
		await queryRunner.query(`DROP TABLE verifiable_presentation`);
	}

	public async down(queryRunner: QueryRunner): Promise<void> { }
}
