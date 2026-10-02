import { MigrationInterface, QueryRunner } from "typeorm";

export class RemoveBackupColumns1790591688456 implements MigrationInterface {
		name = 'RemoveBackupColumns1790591688456'

		public async up(queryRunner: QueryRunner): Promise<void> {
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` DROP COLUMN \`backupEligibility\``);
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` DROP COLUMN \`backupState\``);
		}

		public async down(queryRunner: QueryRunner): Promise<void> {
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` ADD \`backupState\` tinyint NOT NULL DEFAULT '0'`);
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` ADD \`backupEligibility\` tinyint NOT NULL DEFAULT '0'`);
		}

}
