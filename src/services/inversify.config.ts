import { Container } from "inversify";
import { TYPES  } from "./types";
import { OpenidCredentialReceiving, OutboundCommunication, WalletKeystore, DidKeyUtilityService, SocketManagerServiceInterface, WalletKeystoreManager } from "./interfaces";
import { OpenidForCredentialIssuanceService } from "./OpenidForCredentialIssuanceService";
import { OpenidForPresentationService } from "./OpenidForPresentationService";
import "reflect-metadata";
import { DatabaseKeystoreService } from "./DatabaseKeystoreService";
import { OpenidForCredentialIssuanceVCEDUService } from "./OpenidForCredentialIssuanceVCEDUService";
import config from "../../config";
import { W3CDidKeyUtilityService } from "./W3CDidKeyUtilityService";
import { VerifierRegistryService } from "./VerifierRegistryService";
import { EBSIDidKeyUtilityService } from "./EBSIDidKeyUtilityService";
import { SocketManagerService } from "./SocketManagerService";
import { ClientKeystoreService } from "./ClientKeystoreService";
import { WalletKeystoreManagerService } from "./WalletKeystoreManagerService";

const appContainer = new Container();


appContainer.bind<WalletKeystore>(TYPES.ClientKeystoreService)
	.to(ClientKeystoreService)

appContainer.bind<WalletKeystore>(TYPES.DatabaseKeystoreService)
	.to(DatabaseKeystoreService)

appContainer.bind<WalletKeystoreManager>(TYPES.WalletKeystoreManagerService)
	.to(WalletKeystoreManagerService)

switch (config.servicesConfiguration.issuanceService) {
case "OpenidForCredentialIssuanceService":
	appContainer.bind<OpenidCredentialReceiving>(TYPES.OpenidForCredentialIssuanceService)
		.to(OpenidForCredentialIssuanceService)
	break;
case "OpenidForCredentialIssuanceVCEDUService":
	appContainer.bind<OpenidCredentialReceiving>(TYPES.OpenidForCredentialIssuanceService)
		.to(OpenidForCredentialIssuanceVCEDUService)
	break;
}

appContainer.bind<OutboundCommunication>(TYPES.OpenidForPresentationService)
	.to(OpenidForPresentationService)


if (!config.servicesConfiguration.didKeyService) {
	throw new Error("config.servicesConfiguration.didKeyService not set on configuration file");
}

switch (config.servicesConfiguration.didKeyService) {
case "W3C":
	appContainer.bind<DidKeyUtilityService>(TYPES.DidKeyUtilityService)
		.to(W3CDidKeyUtilityService)
	break;
case "EBSI":
	appContainer.bind<DidKeyUtilityService>(TYPES.DidKeyUtilityService)
		.to(EBSIDidKeyUtilityService)
	break;
default:
	throw new Error("config.servicesConfiguration.didKeyService must have value 'EBSI' or 'W3C'");
}

appContainer.bind<VerifierRegistryService>(TYPES.VerifierRegistryService)
	.to(VerifierRegistryService)


appContainer.bind<SocketManagerServiceInterface>(TYPES.SocketManagerService)
	.to(SocketManagerService)

export { appContainer }