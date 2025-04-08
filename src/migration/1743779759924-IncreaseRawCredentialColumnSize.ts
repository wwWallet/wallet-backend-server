import { MigrationInterface, QueryRunner } from "typeorm";

export class IncreaseRawCredentialColumnSize1743779759924 implements MigrationInterface {
	name = 'IncreaseRawCredentialColumnSize1743779759924'

	public async up(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`
      ALTER TABLE verifiable_credential
      MODIFY COLUMN credential MEDIUMBLOB;
    `);
	}

	public async down(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`
      ALTER TABLE verifiable_credential
      MODIFY COLUMN credential BLOB;
    `);
	}

}
