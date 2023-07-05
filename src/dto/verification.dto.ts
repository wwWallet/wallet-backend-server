export type VerifyVpRequestDTO = {
	format: 'jwt_vp' | 'ldp_vp';
	vpjwt: string;
}

export type VerifyVpResponseDTO = {
	verificationResult: boolean;
}