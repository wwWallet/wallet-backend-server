import { MigrationInterface, QueryRunner } from "typeorm";

export class AddSyncableToWebauthnCredential1782737022760 implements MigrationInterface {

	public async up(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`ALTER TABLE \`webauthn_credential\` ADD \`backupEligibility\` BOOLEAN NOT NULL DEFAULT 0`);
		await queryRunner.query(`ALTER TABLE \`webauthn_credential\` ADD \`backupState\` BOOLEAN NOT NULL DEFAULT 0`);
	}

	public async down(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`ALTER TABLE \`webauthn_credential\` DROP COLUMN \`backupEligibility\``);
		await queryRunner.query(`ALTER TABLE \`webauthn_credential\` DROP COLUMN \`backupState\``);
	}
}
