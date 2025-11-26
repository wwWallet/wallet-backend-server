import { MigrationInterface, QueryRunner } from "typeorm";

export class InitSchema1762258689036 implements MigrationInterface {
		name = 'InitSchema1762258689036'

		public async up(queryRunner: QueryRunner): Promise<void> {
				await queryRunner.query(`CREATE TABLE \`fcm_token\` (\`id\` int NOT NULL AUTO_INCREMENT, \`value\` varchar(255) NOT NULL, \`userId\` int NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
				await queryRunner.query(`CREATE TABLE \`user\` (\`id\` int NOT NULL AUTO_INCREMENT, \`webauthnUserHandle\` varchar(36) NOT NULL, \`username\` varchar(255) NULL DEFAULT NULL, \`displayName\` varchar(255) NULL DEFAULT NULL, \`did\` varchar(255) NOT NULL, \`passwordHash\` varchar(255) NULL DEFAULT NULL, \`keys\` blob NOT NULL, \`isAdmin\` tinyint NOT NULL DEFAULT 0, \`privateData\` mediumblob NOT NULL, \`walletType\` enum ('0', '1') NOT NULL DEFAULT '0', \`openidRefreshTokenMaxAgeInSeconds\` int NOT NULL DEFAULT '0', UNIQUE INDEX \`IDX_cace4a159ff9f2512dd4237376\` (\`id\`), UNIQUE INDEX \`IDX_3413a4565c00e01b445c3d76ea\` (\`webauthnUserHandle\`), UNIQUE INDEX \`IDX_78a916df40e02a9deb1c4b75ed\` (\`username\`), UNIQUE INDEX \`IDX_7d4ee7205853cfea0f68240b58\` (\`did\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
				await queryRunner.query(`CREATE TABLE \`webauthn_credential\` (\`id\` varchar(36) NOT NULL, \`credentialId\` blob NOT NULL, \`userHandle\` blob NOT NULL, \`nickname\` varchar(255) NULL DEFAULT NULL, \`createTime\` datetime NOT NULL, \`lastUseTime\` datetime NOT NULL, \`publicKeyCose\` blob NOT NULL, \`signatureCount\` int NOT NULL, \`transports\` text NOT NULL, \`attestationObject\` blob NOT NULL, \`create_clientDataJSON\` blob NOT NULL, \`prfCapable\` tinyint NOT NULL, \`userId\` int NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
				await queryRunner.query(`CREATE TABLE \`verifier\` (\`id\` int NOT NULL AUTO_INCREMENT, \`name\` varchar(255) NOT NULL, \`url\` varchar(255) NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
				await queryRunner.query(`CREATE TABLE \`verifiable_presentation\` (\`id\` int NOT NULL AUTO_INCREMENT, \`holderDID\` varchar(255) NOT NULL, \`presentationIdentifier\` varchar(255) NOT NULL, \`presentation\` blob NOT NULL, \`presentationSubmission\` blob NOT NULL, \`includedVerifiableCredentialIdentifiers\` blob NOT NULL, \`audience\` varchar(255) NOT NULL DEFAULT '', \`issuanceDate\` datetime NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
				await queryRunner.query(`CREATE TABLE \`verifiable_credential\` (\`id\` int NOT NULL AUTO_INCREMENT, \`holderDID\` varchar(255) NOT NULL, \`credentialIdentifier\` varchar(255) NOT NULL, \`credential\` blob NOT NULL, \`format\` varchar(255) NOT NULL, \`credentialConfigurationId\` varchar(255) NOT NULL DEFAULT '', \`credentialIssuerIdentifier\` varchar(255) NOT NULL DEFAULT '', \`instanceId\` smallint NOT NULL DEFAULT '0', \`sigCount\` smallint NOT NULL DEFAULT '0', PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
				await queryRunner.query(`CREATE TABLE \`trusted_root_certificate\` (\`id\` int NOT NULL AUTO_INCREMENT, \`certificate\` blob NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
				await queryRunner.query(`CREATE TABLE \`webauthn_challenge\` (\`id\` varchar(255) NOT NULL, \`type\` varchar(255) NOT NULL, \`userHandle\` varchar(255) NULL DEFAULT NULL, \`challenge\` blob NOT NULL, \`prfSalt\` blob NULL DEFAULT NULL, \`createTime\` datetime NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
				await queryRunner.query(`CREATE TABLE \`credential_issuer\` (\`id\` int NOT NULL AUTO_INCREMENT, \`credentialIssuerIdentifier\` varchar(255) NOT NULL, \`clientId\` varchar(255) NULL DEFAULT NULL, \`visible\` tinyint NULL DEFAULT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
				await queryRunner.query(`ALTER TABLE \`fcm_token\` ADD CONSTRAINT \`FK_eda4e3fc14adda28b0c06e095cd\` FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`);
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` ADD CONSTRAINT \`FK_c3d25feb0b3f72d22eeb98f9de1\` FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`);
		}

		public async down(queryRunner: QueryRunner): Promise<void> {
				await queryRunner.query(`ALTER TABLE \`webauthn_credential\` DROP FOREIGN KEY \`FK_c3d25feb0b3f72d22eeb98f9de1\``);
				await queryRunner.query(`ALTER TABLE \`fcm_token\` DROP FOREIGN KEY \`FK_eda4e3fc14adda28b0c06e095cd\``);
				await queryRunner.query(`DROP TABLE \`credential_issuer\``);
				await queryRunner.query(`DROP TABLE \`webauthn_challenge\``);
				await queryRunner.query(`DROP TABLE \`trusted_root_certificate\``);
				await queryRunner.query(`DROP TABLE \`verifiable_credential\``);
				await queryRunner.query(`DROP TABLE \`verifiable_presentation\``);
				await queryRunner.query(`DROP TABLE \`verifier\``);
				await queryRunner.query(`DROP TABLE \`webauthn_credential\``);
				await queryRunner.query(`DROP INDEX \`IDX_7d4ee7205853cfea0f68240b58\` ON \`user\``);
				await queryRunner.query(`DROP INDEX \`IDX_78a916df40e02a9deb1c4b75ed\` ON \`user\``);
				await queryRunner.query(`DROP INDEX \`IDX_3413a4565c00e01b445c3d76ea\` ON \`user\``);
				await queryRunner.query(`DROP INDEX \`IDX_cace4a159ff9f2512dd4237376\` ON \`user\``);
				await queryRunner.query(`DROP TABLE \`user\``);
				await queryRunner.query(`DROP TABLE \`fcm_token\``);
		}

}
