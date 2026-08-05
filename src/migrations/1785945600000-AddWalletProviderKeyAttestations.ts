import { MigrationInterface, QueryRunner } from "typeorm";

export class AddWalletProviderKeyAttestations1785945600000 implements MigrationInterface {
	name = "AddWalletProviderKeyAttestations1785945600000";

	public async up(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`CREATE TABLE \`wallet_instance\` (\`id\` varchar(36) NOT NULL, \`userId\` varchar(36) NOT NULL, \`walletName\` varchar(255) NOT NULL, \`walletVersion\` varchar(64) NOT NULL, \`state\` varchar(32) NOT NULL, \`activationEvidenceReference\` varchar(255) NOT NULL, \`activationEvidenceHash\` char(64) NOT NULL, \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), \`revokedAt\` datetime NULL DEFAULT NULL, \`revocationReason\` varchar(512) NULL DEFAULT NULL, INDEX \`IDX_wallet_instance_user_state\` (\`userId\`, \`state\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
		await queryRunner.query(`CREATE TABLE \`wallet_provider_status_list\` (\`id\` int NOT NULL AUTO_INCREMENT, \`kind\` varchar(16) NOT NULL, \`capacity\` int UNSIGNED NOT NULL, \`nextIndex\` int UNSIGNED NOT NULL DEFAULT 0, \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), INDEX \`IDX_wallet_provider_status_list_allocation\` (\`kind\`, \`nextIndex\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
		await queryRunner.query(`CREATE TABLE \`key_attestation\` (\`id\` varchar(36) NOT NULL, \`walletInstanceId\` varchar(36) NOT NULL, \`statusListId\` int NOT NULL, \`statusListIndex\` int UNSIGNED NOT NULL, \`evidenceReference\` varchar(255) NOT NULL, \`evidenceHash\` char(64) NOT NULL, \`tokenHash\` char(64) NOT NULL, \`issuedAt\` datetime NOT NULL, \`tokenExpiresAt\` datetime NOT NULL, \`maintenanceExpiresAt\` datetime NOT NULL, \`consumedAt\` datetime NULL DEFAULT NULL, \`revoked\` tinyint NOT NULL DEFAULT 0, INDEX \`IDX_key_attestation_wallet_instance\` (\`walletInstanceId\`), UNIQUE INDEX \`IDX_key_attestation_status_entry\` (\`statusListId\`, \`statusListIndex\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
		await queryRunner.query(`CREATE TABLE \`key_attestation_attested_key\` (\`thumbprint\` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, \`keyAttestationId\` varchar(36) NOT NULL, \`publicJwk\` text NOT NULL, INDEX \`IDX_attested_key_attestation\` (\`keyAttestationId\`), PRIMARY KEY (\`thumbprint\`)) ENGINE=InnoDB`);
		await queryRunner.query(`ALTER TABLE \`key_attestation\` ADD CONSTRAINT \`FK_key_attestation_wallet_instance\` FOREIGN KEY (\`walletInstanceId\`) REFERENCES \`wallet_instance\`(\`id\`) ON DELETE RESTRICT ON UPDATE NO ACTION`);
		await queryRunner.query(`ALTER TABLE \`key_attestation\` ADD CONSTRAINT \`FK_key_attestation_status_list\` FOREIGN KEY (\`statusListId\`) REFERENCES \`wallet_provider_status_list\`(\`id\`) ON DELETE RESTRICT ON UPDATE NO ACTION`);
		await queryRunner.query(`ALTER TABLE \`key_attestation_attested_key\` ADD CONSTRAINT \`FK_attested_key_attestation\` FOREIGN KEY (\`keyAttestationId\`) REFERENCES \`key_attestation\`(\`id\`) ON DELETE RESTRICT ON UPDATE NO ACTION`);
	}

	public async down(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`ALTER TABLE \`key_attestation_attested_key\` DROP FOREIGN KEY \`FK_attested_key_attestation\``);
		await queryRunner.query(`ALTER TABLE \`key_attestation\` DROP FOREIGN KEY \`FK_key_attestation_status_list\``);
		await queryRunner.query(`ALTER TABLE \`key_attestation\` DROP FOREIGN KEY \`FK_key_attestation_wallet_instance\``);
		await queryRunner.query(`DROP TABLE \`key_attestation_attested_key\``);
		await queryRunner.query(`DROP TABLE \`key_attestation\``);
		await queryRunner.query(`DROP TABLE \`wallet_provider_status_list\``);
		await queryRunner.query(`DROP TABLE \`wallet_instance\``);
	}
}
