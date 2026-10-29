import { DataSource } from 'typeorm';
import { config } from '../config';
import { logger } from './logger';

const log = logger.child({ module: 'DB' });

// Initialize DB connection
const AppDataSource: DataSource = new DataSource({
	type: 'mysql',
	host: config.db.host,
	port: config.db.port,
	username: config.db.username,
	password: config.db.password,
	database: config.db.dbname,
	entities: [__dirname + '/entities/*.entity.{js,ts}'],
	migrations: [__dirname + '/migrations/*.{js,ts}'],
	synchronize: false,
});

(async function initDataSource() {
	let connected = false;

	log.info('Connecting with DB...');
	await AppDataSource.initialize()
		.then(() => {
			log.info('App Data Source has been initialized!');
			connected = true;
		})
		.catch((err) => {
			log.error({ err }, 'Error during Data Source initialization');
		});

	// if not connected, then retry in loop
	while (!connected) {
		await new Promise((resolve) => setTimeout(resolve, 3000)).then(async () => {
			await AppDataSource.initialize()
				.then(() => {
					log.info('App Data Source has been initialized!');
					connected = true;
				})
				.catch((err) => {
					log.fatal({ err }, 'Error during Data Source initialization');
				});
		});
	}
})();

export default AppDataSource;
