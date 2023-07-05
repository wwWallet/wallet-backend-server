export type OutboundRequest = {
	redirect_to?: string;
	conformantCredentialsMap?: Map<string, string[]>
	verifierDomainName?: string
}
