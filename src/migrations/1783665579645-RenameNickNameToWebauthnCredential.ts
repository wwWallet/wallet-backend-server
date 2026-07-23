import { MigrationInterface, QueryRunner } from "typeorm";

export class RenameNickNameToWebauthnCredential implements MigrationInterface {

	public async up(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`ALTER TABLE \'webauthn_credential\' RENAME COLUMN \'nickname\' TO \'name\';`);
	}

	public async down(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`ALTER TABLE \'webauthn_credential\' RENAME COLUMN \'name\' TO \'nickname\';`);
	}
}
