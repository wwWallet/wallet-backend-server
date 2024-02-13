import { EntityManager } from "typeorm"

import AppDataSource from "../AppDataSource";

/**
	* Run the provided callback in a database transaction. The `entityManager` can
	* be passed as an argument down the call stack to make the transaction cover
	* any database operation that can take the `EntityManager` to use as an
	* argument.
	*
	* This function accepts `Err` `Result`s to signal that the transaction should
	* be aborted, in addition to the conventional signals of throwing an exception
	* or returning a rejected `Promise`.
	*/
export async function runTransaction<T>(runInTransaction: (entityManager: EntityManager) => Promise<T>): Promise<T> {
	return await AppDataSource.manager.transaction(async (entityManager) => {
		const result = await runInTransaction(entityManager);
		if ("err" in result && "val" in result) {
			if (result["err"]) {
				return Promise.reject(result["val"]);
			}
		}
	});
}
