import { Container } from "inversify";
import { TYPES  } from "./types";
import { WalletKeystore, SocketManagerServiceInterface, WalletKeystoreManager } from "./interfaces";
import "reflect-metadata";
import { SocketManagerService } from "./SocketManagerService";
import { ClientKeystoreService } from "./ClientKeystoreService";
import { WalletKeystoreManagerService } from "./WalletKeystoreManagerService";

const appContainer = new Container();


appContainer.bind<WalletKeystore>(TYPES.ClientKeystoreService)
	.to(ClientKeystoreService)


appContainer.bind<WalletKeystoreManager>(TYPES.WalletKeystoreManagerService)
	.to(WalletKeystoreManagerService)



appContainer.bind<SocketManagerServiceInterface>(TYPES.SocketManagerService)
	.to(SocketManagerService)

export { appContainer }
