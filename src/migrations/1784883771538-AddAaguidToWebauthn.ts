import { MigrationInterface, QueryRunner } from "typeorm";

export class AddAaguidToWebauthn1784883771538 implements MigrationInterface {
		name = 'AddAaguidToWebauthn1784883771538'

		public async up(queryRunner: QueryRunner): Promise<void> {
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` CHANGE \`aaguid\` \`aaguid\` varchar(36) NULL`);
		}

		public async down(queryRunner: QueryRunner): Promise<void> {
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` CHANGE \`aaguid\` \`aaguid\` varchar(36) NULL DEFAULT 'NULL'`);
		}

}
