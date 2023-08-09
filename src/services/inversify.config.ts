import { Container } from "inversify";
import { TYPES  } from "./types";
import { OpenidCredentialReceiving, LegalPersonsRegistry, OutboundCommunication, WalletKeystore } from "./interfaces";
import { OpenidForCredentialIssuanceService } from "./OpenidForCredentialIssuanceService";
import { OpenidForPresentationService } from "./OpenidForPresentationService";
import "reflect-metadata";
import { DatabaseKeystoreService } from "./DatabaseKeystoreService";
import { OpenidForCredentialIssuanceMattrV2Service } from "./OpenidForCredentialIssuanceMattrV2Service";
import config from "../../config";

const appContainer = new Container();


appContainer.bind<WalletKeystore>(TYPES.WalletKeystore)
	.to(DatabaseKeystoreService)


// appContainer.bind<LegalPersonsRegistry>(TYPES.LegalPersonsRegistry)
// 	.to(LegalPersonService)
	// .whenTargetNamed(LegalPersonService.identifier);



console.log("Service name  = ", config.servicesConfiguration.issuanceService)
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

export { appContainer }


// example usage
// const openidForCredentialIssuanceService = appContainer.getNamed<OpenidCredentialReceiving>(TYPES.OpenidCredentialReceiving, OpenidForCredentialIssuanceService.identifier);
