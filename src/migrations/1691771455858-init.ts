import { MigrationInterface, QueryRunner } from "typeorm";

export class init1691771455858 implements MigrationInterface {
    name = 'init1691771455858'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE \`legal_person\` (\`id\` int NOT NULL AUTO_INCREMENT, \`friendlyName\` varchar(255) NOT NULL, \`url\` varchar(255) NOT NULL, \`did\` varchar(255) NOT NULL, \`client_id\` varchar(255) NULL DEFAULT NULL, \`client_secret\` varchar(255) NULL DEFAULT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`user\` (\`id\` int NOT NULL AUTO_INCREMENT, \`username\` varchar(255) NOT NULL, \`did\` varchar(255) NOT NULL, \`passwordHash\` varchar(255) NOT NULL, \`keys\` blob NOT NULL, \`fcmToken\` blob NULL DEFAULT NULL, \`browserFcmToken\` blob NULL DEFAULT NULL, \`isAdmin\` tinyint NOT NULL DEFAULT 0, UNIQUE INDEX \`IDX_78a916df40e02a9deb1c4b75ed\` (\`username\`), UNIQUE INDEX \`IDX_7d4ee7205853cfea0f68240b58\` (\`did\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`verifiable_credential\` (\`id\` int NOT NULL AUTO_INCREMENT, \`holderDID\` varchar(255) NOT NULL, \`credentialIdentifier\` varchar(255) NOT NULL, \`credential\` blob NOT NULL, \`issuerDID\` varchar(255) NOT NULL, \`issuerURL\` varchar(255) NOT NULL, \`issuerFriendlyName\` varchar(255) NOT NULL, \`format\` varchar(255) NOT NULL, \`logoURL\` varchar(255) NOT NULL, \`backgroundColor\` varchar(255) NOT NULL, \`issuanceDate\` datetime NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`verifiable_presentation\` (\`id\` int NOT NULL AUTO_INCREMENT, \`presentationIdentifier\` varchar(255) NOT NULL, \`presentation\` blob NOT NULL, \`holderDID\` varchar(255) NOT NULL, \`audience\` varchar(255) NOT NULL DEFAULT '', \`format\` varchar(255) NOT NULL DEFAULT 'jwt_vp', \`includedVerifiableCredentialIdentifiers\` blob NOT NULL, \`presentationSubmission\` blob NOT NULL, \`issuanceDate\` datetime NOT NULL, PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP TABLE \`verifiable_presentation\``);
        await queryRunner.query(`DROP TABLE \`verifiable_credential\``);
        await queryRunner.query(`DROP INDEX \`IDX_7d4ee7205853cfea0f68240b58\` ON \`user\``);
        await queryRunner.query(`DROP INDEX \`IDX_78a916df40e02a9deb1c4b75ed\` ON \`user\``);
        await queryRunner.query(`DROP TABLE \`user\``);
        await queryRunner.query(`DROP TABLE \`legal_person\``);
    }

}
