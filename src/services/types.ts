import "reflect-metadata";

const TYPES = {

	WalletKeystore: Symbol.for("WalletKeystore"),
	// DatabaseKeystoreService: Symbol.for("DatabaseKeystoreService"),


	// OpenidCredentialReceiving: Symbol.for("OpenidCredentialReceiving"),
	OpenidForCredentialIssuanceService: Symbol.for("OpenidForCredentialIssuanceService"),


	// OutboundCommunication: Symbol.for("OutboundCommunication"),
	OpenidForPresentationService: Symbol.for("OpenidForPresentationService"),


	DidKeyUtilityService: Symbol.for("DidKeyUtilityService"),
	VerifierRegistryService: Symbol.for("VerifierRegistryService"),
	SocketManagerService: Symbol.for("SocketManagerService")

};

export { TYPES };