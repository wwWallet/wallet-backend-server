import { MigrationInterface, QueryRunner } from "typeorm";

export class AddAaguidToWebauthnCredential1787219977415 implements MigrationInterface {
		name = 'AddAaguidToWebauthnCredential1787219977415'

		public async up(queryRunner: QueryRunner): Promise<void> {
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` ADD \`aaguid\` varchar(36) NULL`);
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` CHANGE \`backupEligibility\` \`backupEligibility\` tinyint NOT NULL`);
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` CHANGE \`backupState\` \`backupState\` tinyint NOT NULL`);
		}

		public async down(queryRunner: QueryRunner): Promise<void> {
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` CHANGE \`backupState\` \`backupState\` tinyint NOT NULL DEFAULT '0'`);
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` CHANGE \`backupEligibility\` \`backupEligibility\` tinyint NOT NULL DEFAULT '0'`);
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` DROP COLUMN \`aaguid\``);
		}

}
