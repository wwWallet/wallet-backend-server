import { MigrationInterface, QueryRunner } from 'typeorm';

export class WalletProviderStatus1791885126942 implements MigrationInterface {
	public async up(queryRunner: QueryRunner): Promise<void> {
		// No user FK: revocation evidence must survive account deletion.
		await queryRunner.query(
			`CREATE TABLE wallet_provider_status_owner (accountId varchar(36) NOT NULL, revoked boolean NOT NULL DEFAULT false, PRIMARY KEY (accountId)) ENGINE=InnoDB`,
		);
		await queryRunner.query(
			`CREATE TABLE wallet_provider_status_cursor (kind varchar(2) NOT NULL, listId varchar(36) NOT NULL, allocatedCount int unsigned NOT NULL DEFAULT 0, PRIMARY KEY (kind)) ENGINE=InnoDB`,
		);
		await queryRunner.query(`INSERT INTO wallet_provider_status_cursor (kind, listId) VALUES ('wa', UUID()), ('ka', UUID())`);
		await queryRunner.query(
			`CREATE TABLE wallet_provider_status_entry (id varchar(36) NOT NULL, accountId varchar(36) NOT NULL, kind varchar(2) NOT NULL, listId varchar(36) NOT NULL, slot int unsigned NOT NULL, maintenanceExp int unsigned NOT NULL, revoked boolean NOT NULL DEFAULT false, PRIMARY KEY (id), UNIQUE KEY status_slot (listId, slot), KEY status_owner (accountId), CONSTRAINT status_owner_fk FOREIGN KEY (accountId) REFERENCES wallet_provider_status_owner (accountId)) ENGINE=InnoDB`,
		);
	}

	public async down(queryRunner: QueryRunner): Promise<void> {
		await queryRunner.query(`DROP TABLE wallet_provider_status_entry`);
		await queryRunner.query(`DROP TABLE wallet_provider_status_cursor`);
		await queryRunner.query(`DROP TABLE wallet_provider_status_owner`);
	}
}
