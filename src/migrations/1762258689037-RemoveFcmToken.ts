import { MigrationInterface, QueryRunner, TableForeignKey } from "typeorm";

export class RemoveFcmToken1762258689037 implements MigrationInterface {
	name = 'RemoveFcmToken1762258689037';

		public async up(queryRunner: QueryRunner): Promise<void> {
			const table = await queryRunner.getTable("fcm_token");
			// Name-agnostic drop of user entity's one-to-many relationship
			if (table) {
				const fk = table.foreignKeys.find(k => k.columnNames.includes("userId"));
				if (fk) await queryRunner.dropForeignKey("fcm_token", fk);
				await queryRunner.query("DROP TABLE `fcm_token`");
			}
		}

		public async down(queryRunner: QueryRunner): Promise<void> {
			await queryRunner.query(`
				CREATE TABLE \`fcm_token\` (
					\`id\` int NOT NULL AUTO_INCREMENT,
					\`value\` varchar(255) NOT NULL,
					\`userId\` int NULL,
					PRIMARY KEY (\`id\`)
				) ENGINE=InnoDB
			`);

			await queryRunner.createForeignKey(
				"fcm_token",
				new TableForeignKey({
					columnNames: ["userId"],
					referencedTableName: "user",
					referencedColumnNames: ["id"],
					onDelete: "NO ACTION",
					onUpdate: "NO ACTION",
				})
			);
		}

}
