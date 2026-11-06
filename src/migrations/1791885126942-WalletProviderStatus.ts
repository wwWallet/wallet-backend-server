import { MigrationInterface, QueryRunner } from 'typeorm';

export class WalletProviderStatus1791885126942 implements MigrationInterface {
	public async up(runner: QueryRunner): Promise<void> {
		await runner.query(`CREATE TABLE wallet_provider_status_list_entry (
			id VARCHAR(36) NOT NULL PRIMARY KEY,
			accountId VARCHAR(36) NOT NULL,
			type VARCHAR(2) NOT NULL,
			listId VARCHAR(43) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
			idx INT UNSIGNED NOT NULL,
			periodStart DATE NOT NULL,
			shard INT UNSIGNED NOT NULL,
			maintenanceExp INT UNSIGNED NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			UNIQUE KEY status_slot (listId, idx),
			KEY status_account (accountId),
			KEY status_discovery (type, periodStart, shard)
		) ENGINE=InnoDB`);
		await runner.query('ALTER TABLE `user` ADD isRevoked BOOLEAN NOT NULL DEFAULT FALSE');
	}

	public async down(runner: QueryRunner): Promise<void> {
		await runner.query('DROP TABLE wallet_provider_status_list_entry');
		await runner.query('ALTER TABLE `user` DROP COLUMN isRevoked');
	}
}
