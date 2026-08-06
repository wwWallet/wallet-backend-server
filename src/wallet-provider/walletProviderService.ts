import crypto from "node:crypto";
import { In } from "typeorm";
import AppDataSource from "../AppDataSource";
import {
	KeyAttestationAttestedKeyEntity,
	KeyAttestationEntity,
	WalletInstanceEntity,
	WalletInstanceState,
	WalletProviderStatusListEntity,
} from "../entities/walletProvider.entity";
import {
	hashJson,
	hashToken,
	PublicJwk,
	signKeyAttestation,
	WalletProviderSigner,
} from "./keyAttestation";
import { WalletProviderEvidenceVerifier } from "./evidenceVerifier";

export class WalletInstanceNotFoundError extends Error { }
export class WalletInstanceRevokedError extends Error { }
export class AttestedKeyAlreadyUsedError extends Error { }
export class KeyAttestationAlreadyConsumedError extends Error { }

type WalletProviderPolicy = {
	baseUrl: string;
	keyAttestationTtlSeconds: number;
	statusMaintenanceSeconds: number;
	maxStatusMaintenanceSeconds: number;
	statusListCapacity: number;
};

export class WalletProviderService {
	constructor(
		private readonly evidenceVerifier: WalletProviderEvidenceVerifier,
		private readonly signer: () => Promise<WalletProviderSigner>,
		private readonly policy: WalletProviderPolicy,
	) {
		if (policy.keyAttestationTtlSeconds >= 24 * 60 * 60) {
			throw new Error("CS-04 key attestations must have a lifetime below 24 hours");
		}
		if (policy.statusListCapacity < 10000) {
			throw new Error("Per-KA status lists must contain at least 10000 entries");
		}
		if (policy.statusMaintenanceSeconds < 31 * 24 * 60 * 60) {
			throw new Error("The default status maintenance period must be at least 31 days");
		}
		if (policy.maxStatusMaintenanceSeconds < policy.statusMaintenanceSeconds) {
			throw new Error("The maximum status maintenance period cannot be below the default");
		}
	}

	async activateWalletInstance(input: {
		userId: string;
		walletName: string;
		walletVersion: string;
		activationEvidence: unknown;
	}): Promise<WalletInstanceEntity> {
		const id = crypto.randomUUID();
		const verifiedEvidence = await this.evidenceVerifier.verifyActivation({
			walletInstanceId: id,
			userId: input.userId,
			walletName: input.walletName,
			walletVersion: input.walletVersion,
			evidence: input.activationEvidence,
		});

		return await AppDataSource.getRepository(WalletInstanceEntity).save({
			id,
			userId: input.userId,
			walletName: input.walletName,
			walletVersion: input.walletVersion,
			state: WalletInstanceState.OPERATIONAL,
			activationEvidenceReference: verifiedEvidence.evidenceReference,
			activationEvidenceHash: hashJson(input.activationEvidence),
		});
	}

	async issueKeyAttestation(input: {
		userId: string;
		walletInstanceId: string;
		jwks: PublicJwk[];
		thumbprints: string[];
		keyEvidence: unknown;
		preferredStatusPeriod?: number;
		nonce?: string;
	}): Promise<{
		id: string;
		keyAttestation: string;
		tokenExpiresAt: number;
		maintenanceExpiresAt: number;
	}> {
		const instance = await AppDataSource.getRepository(WalletInstanceEntity).findOneBy({
			id: input.walletInstanceId,
			userId: input.userId,
		});
		this.assertOperationalInstance(instance);

		const verifiedEvidence = await this.evidenceVerifier.verifyKeys({
			walletInstanceId: instance.id,
			userId: input.userId,
			activationEvidenceReference: instance.activationEvidenceReference,
			jwks: input.jwks,
			thumbprints: input.thumbprints,
			evidence: input.keyEvidence,
		});
		const walletProviderSigner = await this.signer();

		return await AppDataSource.manager.transaction(async manager => {
			const lockedInstance = await manager.getRepository(WalletInstanceEntity)
				.createQueryBuilder("instance")
				.setLock("pessimistic_write")
				.where("instance.id = :id", { id: input.walletInstanceId })
				.andWhere("instance.userId = :userId", { userId: input.userId })
				.getOne();
			this.assertOperationalInstance(lockedInstance);

			const existingKeys = await manager.getRepository(KeyAttestationAttestedKeyEntity)
				.findBy({ thumbprint: In(input.thumbprints) });
			if (existingKeys.length > 0) {
				throw new AttestedKeyAlreadyUsedError("An attested public key was already included in another key attestation");
			}

			const statusEntry = await this.allocateStatusEntry(manager);
			const issuedAt = Math.floor(Date.now() / 1000);
			const tokenExpiresAt = issuedAt + this.policy.keyAttestationTtlSeconds;
			const requestedMaintenance = input.preferredStatusPeriod ?? 0;
			const maintenancePeriod = Math.max(this.policy.statusMaintenanceSeconds, requestedMaintenance);
			if (maintenancePeriod > this.policy.maxStatusMaintenanceSeconds) {
				throw new RangeError("The requested status maintenance period exceeds Wallet Provider policy");
			}
			const maintenanceExpiresAt = issuedAt + maintenancePeriod;
			const id = crypto.randomUUID();
			const statusListUri = this.statusListUri(statusEntry.statusListId);
			const keyAttestation = await signKeyAttestation({
				id,
				issuedAt,
				expiresAt: tokenExpiresAt,
				attestedKeys: input.jwks,
				verifiedEvidence,
				statusListIndex: statusEntry.statusListIndex,
				statusListUri,
				statusMaintenanceExpiresAt: maintenanceExpiresAt,
				nonce: input.nonce,
			}, walletProviderSigner);

			await manager.getRepository(KeyAttestationEntity).save({
				id,
				walletInstanceId: input.walletInstanceId,
				statusListId: statusEntry.statusListId,
				statusListIndex: statusEntry.statusListIndex,
				evidenceReference: verifiedEvidence.evidenceReference,
				evidenceHash: hashJson(input.keyEvidence),
				tokenHash: hashToken(keyAttestation),
				issuedAt: new Date(issuedAt * 1000),
				tokenExpiresAt: new Date(tokenExpiresAt * 1000),
				maintenanceExpiresAt: new Date(maintenanceExpiresAt * 1000),
				revoked: false,
			});
			await manager.getRepository(KeyAttestationAttestedKeyEntity).save(
				input.thumbprints.map((thumbprint, index) => ({
					thumbprint,
					keyAttestationId: id,
					publicJwk: input.jwks[index],
				})),
			);

			return { id, keyAttestation, tokenExpiresAt, maintenanceExpiresAt };
		}).catch(error => {
			if (isDuplicateKeyError(error)) {
				throw new AttestedKeyAlreadyUsedError("An attested public key was already included in another key attestation");
			}
			throw error;
		});
	}

	async consumeKeyAttestation(userId: string, id: string): Promise<void> {
		await AppDataSource.manager.transaction(async manager => {
			const attestation = await manager.getRepository(KeyAttestationEntity)
				.createQueryBuilder("attestation")
				.innerJoin(WalletInstanceEntity, "instance", "instance.id = attestation.walletInstanceId")
				.setLock("pessimistic_write")
				.where("attestation.id = :id", { id })
				.andWhere("instance.userId = :userId", { userId })
				.getOne();
			if (!attestation) {
				throw new WalletInstanceNotFoundError("Key attestation was not found");
			}
			if (attestation.consumedAt) {
				throw new KeyAttestationAlreadyConsumedError("Key attestation was already consumed");
			}
			attestation.consumedAt = new Date();
			await manager.save(attestation);
		});
	}

	async revokeWalletInstance(userId: string, id: string, reason: string): Promise<void> {
		await AppDataSource.manager.transaction(async manager => {
			const instance = await manager.getRepository(WalletInstanceEntity)
				.createQueryBuilder("instance")
				.setLock("pessimistic_write")
				.where("instance.id = :id", { id })
				.andWhere("instance.userId = :userId", { userId })
				.getOne();
			if (!instance) {
				throw new WalletInstanceNotFoundError("Wallet Instance was not found");
			}
			if (instance.state === WalletInstanceState.REVOKED) {
				return;
			}

			instance.state = WalletInstanceState.REVOKED;
			instance.revokedAt = new Date();
			instance.revocationReason = reason;
			await manager.save(instance);
			await manager.getRepository(KeyAttestationEntity).update(
				{ walletInstanceId: instance.id },
				{ revoked: true },
			);
		});
	}

	async getStatusList(id: number): Promise<{
		capacity: number;
		invalidIndexes: number[];
	}> {
		const statusList = await AppDataSource.getRepository(WalletProviderStatusListEntity).findOneBy({ id, kind: "ka" });
		if (!statusList) {
			throw new WalletInstanceNotFoundError("Status List was not found");
		}
		const revokedAttestations = await AppDataSource.getRepository(KeyAttestationEntity).find({
			select: { statusListIndex: true },
			where: { statusListId: id, revoked: true },
		});
		return {
			capacity: statusList.capacity,
			invalidIndexes: revokedAttestations.map(attestation => attestation.statusListIndex),
		};
	}

	statusListUri(id: number): string {
		const baseUrl = this.policy.baseUrl.endsWith("/") ? this.policy.baseUrl : `${this.policy.baseUrl}/`;
		return new URL(`wallet-provider/status/ka/${id}`, baseUrl).toString();
	}

	private async allocateStatusEntry(manager: import("typeorm").EntityManager): Promise<{
		statusListId: number;
		statusListIndex: number;
	}> {
		let statusList = await manager.getRepository(WalletProviderStatusListEntity)
			.createQueryBuilder("statusList")
			.setLock("pessimistic_write")
			.where("statusList.kind = :kind", { kind: "ka" })
			.andWhere("statusList.nextIndex < statusList.capacity")
			.orderBy("statusList.id", "DESC")
			.getOne();

		if (!statusList) {
			statusList = await manager.getRepository(WalletProviderStatusListEntity).save({
				kind: "ka",
				capacity: this.policy.statusListCapacity,
				nextIndex: 0,
			});
		}

		const statusListIndex = statusList.nextIndex;
		statusList.nextIndex += 1;
		await manager.save(WalletProviderStatusListEntity, statusList);
		return { statusListId: statusList.id, statusListIndex };
	}

	private assertOperationalInstance(instance: WalletInstanceEntity | null): asserts instance is WalletInstanceEntity {
		if (!instance) {
			throw new WalletInstanceNotFoundError("Wallet Instance was not found");
		}
		if (instance.state !== WalletInstanceState.OPERATIONAL) {
			throw new WalletInstanceRevokedError("Wallet Instance is revoked");
		}
	}
}

function isDuplicateKeyError(error: unknown): boolean {
	return typeof error === "object" && error !== null && "code" in error && error.code === "ER_DUP_ENTRY";
}
