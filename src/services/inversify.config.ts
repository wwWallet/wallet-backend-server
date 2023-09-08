import { Container } from "inversify";
import { TYPES  } from "./types";
import { OpenidCredentialReceiving, OutboundCommunication, WalletKeystore, DidKeyUtilityService } from "./interfaces";
import { OpenidForCredentialIssuanceService } from "./OpenidForCredentialIssuanceService";
import { OpenidForPresentationService } from "./OpenidForPresentationService";
import "reflect-metadata";
import { DatabaseKeystoreService } from "./DatabaseKeystoreService";
import { OpenidForCredentialIssuanceMattrV2Service } from "./OpenidForCredentialIssuanceMattrV2Service";
import config from "../../config";
import { W3CDidKeyUtilityService } from "./W3CDidKeyUtilityService";
import { VerifierRegistryService } from "./VerifierRegistryService";
import { EBSIDidKeyUtilityService } from "./EBSIDidKeyUtilityService";

const appContainer = new Container();


appContainer.bind<WalletKeystore>(TYPES.WalletKeystore)
	.to(DatabaseKeystoreService)

switch (config.servicesConfiguration.issuanceService) {
case "OpenidForCredentialIssuanceService":
	appContainer.bind<OpenidCredentialReceiving>(TYPES.OpenidForCredentialIssuanceService)
		.to(OpenidForCredentialIssuanceService)
	break;
case "OpenidForCredentialIssuanceMattrV2Service":
	appContainer.bind<OpenidCredentialReceiving>(TYPES.OpenidForCredentialIssuanceService)
		.to(OpenidForCredentialIssuanceMattrV2Service)
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

export { appContainer }