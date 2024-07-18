import "reflect-metadata";

const TYPES = {

	DatabaseKeystoreService: Symbol.for("DatabaseKeystoreService"),
	ClientKeystoreService: Symbol.for("ClientKeystoreService"),
	WalletKeystoreManagerService: Symbol.for("WalletKeystoreManagerService"),


	// OpenidCredentialReceiving: Symbol.for("OpenidCredentialReceiving"),
	OpenidForCredentialIssuanceService: Symbol.for("OpenidForCredentialIssuanceService"),


	// OutboundCommunication: Symbol.for("OutboundCommunication"),
	OpenidForPresentationService: Symbol.for("OpenidForPresentationService"),


	DidKeyUtilityService: Symbol.for("DidKeyUtilityService"),
	VerifierRegistryService: Symbol.for("VerifierRegistryService"),
	SocketManagerService: Symbol.for("SocketManagerService")

};

export { TYPES };
