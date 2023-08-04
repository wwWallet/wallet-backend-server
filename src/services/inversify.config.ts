import { Container } from "inversify";
import { TYPES  } from "./types";
import { OpenidCredentialReceiving, LegalPersonsRegistry, OutboundCommunication, WalletKeystore } from "./interfaces";
import { OpenidForCredentialIssuanceService } from "./OpenidForCredentialIssuanceService";
import { OpenidForPresentationService } from "./OpenidForPresentationService";
import "reflect-metadata";
import { DatabaseKeystoreService } from "./DatabaseKeystoreService";
import { OpenidForCredentialIssuanceMattrService } from "./OpenidForCredentialIssuanceMattrService";

const appContainer = new Container();


appContainer.bind<WalletKeystore>(TYPES.WalletKeystore)
	.to(DatabaseKeystoreService)


// appContainer.bind<LegalPersonsRegistry>(TYPES.LegalPersonsRegistry)
// 	.to(LegalPersonService)
	// .whenTargetNamed(LegalPersonService.identifier);

	
appContainer.bind<OpenidCredentialReceiving>(TYPES.OpenidForCredentialIssuanceService)
	.to(OpenidForCredentialIssuanceMattrService)
	// .whenTargetNamed(OpenidForCredentialIssuanceService.identifier);

appContainer.bind<OutboundCommunication>(TYPES.OpenidForPresentationService)
	.to(OpenidForPresentationService)
	// .whenTargetNamed(OpenidForPresentationService.identifier);


export { appContainer }


// example usage
// const openidForCredentialIssuanceService = appContainer.getNamed<OpenidCredentialReceiving>(TYPES.OpenidCredentialReceiving, OpenidForCredentialIssuanceService.identifier);
