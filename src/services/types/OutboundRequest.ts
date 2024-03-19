export type OutboundRequest = {
	redirect_to?: string;
	conformantCredentialsMap?: Map<string, { credentials: string[], requestedFields: string[] }>
	verifierDomainName?: string
}
