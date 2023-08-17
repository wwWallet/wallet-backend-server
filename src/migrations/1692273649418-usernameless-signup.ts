import { MigrationInterface, QueryRunner } from "typeorm";

export class usernamelessSignup1692273649418 implements MigrationInterface {
    name = 'usernamelessSignup1692273649418'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` CHANGE \`username\` \`username\` varchar(255) NULL DEFAULT NULL`);
        await queryRunner.query(`ALTER TABLE \`user\` CHANGE \`passwordHash\` \`passwordHash\` varchar(255) NULL DEFAULT NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` CHANGE \`passwordHash\` \`passwordHash\` varchar(255) NOT NULL`);
        await queryRunner.query(`ALTER TABLE \`user\` CHANGE \`username\` \`username\` varchar(255) NOT NULL`);
    }

}
