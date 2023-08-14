import { MigrationInterface, QueryRunner } from "typeorm";

export class webauthn1692268301831 implements MigrationInterface {
    name = 'webauthn1692268301831'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE \`webauthn_credential\` (\`id\` varchar(36) NOT NULL, \`credentialId\` blob NOT NULL, \`userHandle\` blob NOT NULL, \`nickname\` varchar(255) NULL DEFAULT NULL, \`createTime\` datetime NOT NULL, \`lastUseTime\` datetime NOT NULL, \`publicKeyCose\` blob NOT NULL, \`signatureCount\` int NOT NULL, \`transports\` text NOT NULL, \`attestationObject\` blob NOT NULL, \`create_clientDataJSON\` blob NOT NULL, \`prfCapable\` tinyint NOT NULL, \`userId\` int NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`webauthn_challenge\` (\`id\` varchar(255) NOT NULL, \`type\` varchar(255) NOT NULL, \`userHandle\` varchar(255) NULL DEFAULT NULL, \`challenge\` blob NOT NULL, \`prfSalt\` blob NULL DEFAULT NULL, \`createTime\` datetime NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`ALTER TABLE \`webauthn_credential\` ADD CONSTRAINT \`FK_c3d25feb0b3f72d22eeb98f9de1\` FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`webauthn_credential\` DROP FOREIGN KEY \`FK_c3d25feb0b3f72d22eeb98f9de1\``);
        await queryRunner.query(`DROP TABLE \`webauthn_challenge\``);
        await queryRunner.query(`DROP TABLE \`webauthn_credential\``);
    }

}
