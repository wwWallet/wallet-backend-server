import { z } from 'zod'

export const authorizationRequestQueryParamsSchema = z.object({
	response_type: z.string(),
	client_id: z.string(),
	redirect_uri: z.string(),
	scope: z.string().optional(),
	authorization_details: z.string(),
	code_challenge: z.string(),
	code_challenge_method: z.string()
});

export const tokenRequestBodySchema = z.object({
	grant_type: z.string(),
	code: z.string().optional(),
	code_verifier: z.string().optional(),
	redirect_uri: z.string().optional(),
	"pre-authorized_code": z.string().optional(),
	user_pin: z.string().optional()
});
export const credentialRequestBodySchema = z.object({
	format: z.string(),
	types: z.array(z.string()), // the specification does not descibe the context and the usage of this parameter
	proof: z.object({
		proof_type: z.string(),
		jwt: z.string()
	})
});



export const tokenResponseSchema = z.object({
	token_type: z.string(),
	access_token: z.string(),
	expires_in: z.number(),
	c_nonce: z.string(),
	c_nonce_expires_in: z.number(),
	id_token: z.string()
});


export const credentialResponseSchema = z.object({
	format: z.string(),
	credential: z.string().optional(),
	acceptance_token: z.string().optional(),
	c_nonce: z.string().optional(),
	c_nonce_expires_in: z.number().optional()
});

export type AuthorizationRequestQueryParamsSchemaType = z.infer<typeof authorizationRequestQueryParamsSchema>;
export type TokenRequestBodySchemaType = z.infer<typeof tokenRequestBodySchema>;
export type CredentialRequestBodySchemaType = z.infer<typeof credentialRequestBodySchema>;

export type TokenResponseSchemaType = z.infer<typeof tokenResponseSchema>;
export type CredentialResponseSchemaType = z.infer<typeof credentialResponseSchema>;
