import {
	Column,
	CreateDateColumn,
	Entity,
	Index,
	PrimaryColumn,
	PrimaryGeneratedColumn,
} from "typeorm";

export enum WalletInstanceState {
	OPERATIONAL = "operational",
	REVOKED = "revoked",
}

@Entity({ name: "wallet_instance" })
@Index(["userId", "state"])
export class WalletInstanceEntity {
	@PrimaryColumn({ type: "varchar", length: 36 })
	id: string;

	@Column({ type: "varchar", length: 36, nullable: false, update: false })
	userId: string;

	@Column({ type: "varchar", length: 255, nullable: false, update: false })
	walletName: string;

	@Column({ type: "varchar", length: 64, nullable: false, update: false })
	walletVersion: string;

	@Column({ type: "varchar", length: 32, nullable: false })
	state: WalletInstanceState;

	@Column({ type: "varchar", length: 255, nullable: false, update: false })
	activationEvidenceReference: string;

	@Column({ type: "char", length: 64, nullable: false, update: false })
	activationEvidenceHash: string;

	@CreateDateColumn({ type: "datetime" })
	createdAt: Date;

	@Column({ type: "datetime", nullable: true, default: () => "NULL" })
	revokedAt?: Date;

	@Column({ type: "varchar", length: 512, nullable: true, default: () => "NULL" })
	revocationReason?: string;
}

@Entity({ name: "wallet_provider_status_list" })
@Index(["kind", "nextIndex"])
export class WalletProviderStatusListEntity {
	@PrimaryGeneratedColumn()
	id: number;

	@Column({ type: "varchar", length: 16, nullable: false, update: false })
	kind: "ka";

	@Column({ type: "int", unsigned: true, nullable: false, update: false })
	capacity: number;

	@Column({ type: "int", unsigned: true, nullable: false, default: 0 })
	nextIndex: number;

	@CreateDateColumn({ type: "datetime" })
	createdAt: Date;
}

@Entity({ name: "key_attestation" })
@Index(["walletInstanceId"])
@Index(["statusListId", "statusListIndex"], { unique: true })
export class KeyAttestationEntity {
	@PrimaryColumn({ type: "varchar", length: 36 })
	id: string;

	@Column({ type: "varchar", length: 36, nullable: false, update: false })
	walletInstanceId: string;

	@Column({ type: "int", nullable: false, update: false })
	statusListId: number;

	@Column({ type: "int", unsigned: true, nullable: false, update: false })
	statusListIndex: number;

	@Column({ type: "varchar", length: 255, nullable: false, update: false })
	evidenceReference: string;

	@Column({ type: "char", length: 64, nullable: false, update: false })
	evidenceHash: string;

	@Column({ type: "char", length: 64, nullable: false, update: false })
	tokenHash: string;

	@Column({ type: "datetime", nullable: false, update: false })
	issuedAt: Date;

	@Column({ type: "datetime", nullable: false, update: false })
	tokenExpiresAt: Date;

	@Column({ type: "datetime", nullable: false, update: false })
	maintenanceExpiresAt: Date;

	@Column({ type: "datetime", nullable: true, default: () => "NULL" })
	consumedAt?: Date;

	@Column({ type: "boolean", nullable: false, default: false })
	revoked: boolean;
}

@Entity({ name: "key_attestation_attested_key" })
@Index(["keyAttestationId"])
export class KeyAttestationAttestedKeyEntity {
	@PrimaryColumn({ type: "varchar", length: 64, charset: "ascii", collation: "ascii_bin" })
	thumbprint: string;

	@Column({ type: "varchar", length: 36, nullable: false, update: false })
	keyAttestationId: string;

	@Column({ type: "simple-json", nullable: false, update: false })
	publicJwk: Record<string, unknown>;
}
