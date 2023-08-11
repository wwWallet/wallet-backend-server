import * as uuid from "uuid";
import { MigrationInterface, QueryRunner } from "typeorm";


export class setWebauthnUserHandle1692039048456 implements MigrationInterface {
    name = 'setWebauthnUserHandle1692039048456'

    public async up(queryRunner: QueryRunner): Promise<void> {
      await Promise.all((await queryRunner.query(`SELECT id from user`, [], true)).records.map(result => (
        queryRunner.query(`UPDATE user SET webauthnUserHandle = ? WHERE id = ?`, [uuid.v4(), result.id])
      )));

      await queryRunner.query(`ALTER TABLE \`user\` CHANGE \`webauthnUserHandle\` \`webauthnUserHandle\` varchar(36) NOT NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`user\` CHANGE \`webauthnUserHandle\` \`webauthnUserHandle\` varchar(36) NULL DEFAULT 'NULL'`);
    }

}
