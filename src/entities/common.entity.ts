import { Result } from "ts-results";
import { EntityManager } from "typeorm"

import AppDataSource from "../AppDataSource";
import { isResult } from "../util/util";

/**
	* Run the provided callback in a database transaction. The `entityManager` can
	* be passed as an argument down the call stack to make the transaction cover
	* any database operation that can take the `EntityManager` to use as an
	* argument.
	*
	* This function accepts `Err` `Result`s to signal that the transaction should
	* be aborted, in addition to the conventional signals of throwing an exception
	* or returning a rejected `Promise`. `Ok<T>` results are unpacked to return
	* just the contained `T` type.
	*/
export async function runTransaction<T, E>(runInTransaction: (entityManager: EntityManager) => Promise<Result<T, E> | T>): Promise<T> {
	return await AppDataSource.manager.transaction(async (entityManager) => {
		const result = await runInTransaction(entityManager);
		if (isResult(result)) {
			if (result.ok) {
				return Promise.resolve(result.val);
			} else {
				return Promise.reject(result.val);
			}
		} else {
			return result;
		}
	});
}
