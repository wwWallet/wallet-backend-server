import { DataSource } from "typeorm";
import config from "../config";


// Initialize DB connection
const AppDataSource: DataSource = new DataSource({
	type: "mysql",
	host: config.db.host,
	port: config.db.port,
	username: config.db.username,
	password: config.db.password,
	database: config.db.dbname,
	entities: [__dirname + "/entities/*.entity.{js,ts}"],
	synchronize: false,
	migrations: [__dirname + "/migrations/*.{js,ts}"],
	migrationsRun: true,
});

(async function initDataSource() {
	let connected = false;

	console.log("Connecting with DB...");
	await AppDataSource.initialize()
		.then(() => {
			console.log("App Data Source has been initialized!");
			connected = true;
		})
		.catch((err) => {
			console.error("Error during Data Source initialization", err);
		});

	// if not connected, then retry in loop
	while (!connected) {
		await new Promise((resolve) => setTimeout(resolve, 3000)).then(async () => {
			await AppDataSource.initialize()
				.then(() => {
					console.log("App Data Source has been initialized!");
					connected = true;
				})
				.catch((err) => {
					console.error("Error during Data Source initialization", err);
				});
		});
	}
})();


export default AppDataSource;
