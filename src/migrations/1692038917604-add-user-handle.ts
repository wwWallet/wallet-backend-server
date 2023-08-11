import { MigrationInterface, QueryRunner } from "typeorm";

export class addUserHandle1692038917604 implements MigrationInterface {
    name = 'addUserHandle1692038917604'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` ADD \`webauthnUserHandle\` varchar(36) NULL DEFAULT NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` DROP COLUMN \`webauthnUserHandle\``);
    }

}
