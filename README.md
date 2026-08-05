
# 1 Development
## Install

```
yarn install
```

## Change configuration

Edit `config/config.dev.ts` file to change the configuration of the app.
## Run in dev mode

```
yarn dev
```

Set `REGISTRATION_DISABLED=true` to omit the public user-registration endpoints from the server. By default, registration remains enabled. This disables `/user/register`, `/user/register-webauthn-begin`, and `/user/register-webauthn-finish`; authenticated passkey-management endpoints remain available.

## Wallet Provider key attestations

The backend implements the CS-04 Wallet Provider lifecycle needed to issue
instance-bound Key Attestations (KAs):

- `POST /wallet-provider/instances/activate`
- `POST /wallet-provider/key-attestations`
- `POST /wallet-provider/key-attestations/{id}/consume`
- `POST /wallet-provider/instances/{id}/revoke`
- `GET /wallet-provider/status/ka/{listId}` (public)

All endpoints except the Status List endpoint require the normal wwWallet app
Bearer token. Run the `AddWalletProviderKeyAttestations` migration before using
them.

Configure a trusted, platform-specific evidence verifier before activation or
KA issuance:

```dotenv
WALLET_PROVIDER_EVIDENCE_VERIFIER_URL=https://integrity.example/verify
WALLET_PROVIDER_EVIDENCE_VERIFIER_BEARER_TOKEN=<secret supplied at deployment>
WALLET_PROVIDER_EVIDENCE_VERIFIER_TIMEOUT_MS=5000
```

The verifier receives either a `wallet_instance_activation` request or a
`key_attestation` request. The latter includes the canonical public JWKs, their
RFC 7638 thumbprints, the authenticated user and Wallet Instance identifiers,
and the opaque evidence supplied by the Wallet Unit. A successful activation
response is:

```json
{
  "verified": true,
  "evidence_reference": "platform-evidence-123"
}
```

A successful key response must return assurance claims derived by the verifier,
not copied from the Wallet Unit:

```json
{
  "verified": true,
  "evidence_reference": "platform-key-evidence-456",
  "key_storage": ["iso_18045_high"],
  "user_authentication": ["iso_18045_high"],
  "certification": "https://certifications.example/wscd/1"
}
```

Return HTTP 401, 403, or 422, or `{ "verified": false }`, to reject evidence.
In production the verifier URL must use HTTPS. The backend stores only evidence
references and SHA-256 hashes, never the raw evidence or issued KA.

The signing key and leaf-to-intermediate certificate chain are configured with:

```dotenv
WALLET_PROVIDER_PRIVATE_KEY_PATH=/run/secrets/wallet-provider.key
WALLET_PROVIDER_CERTIFICATE_CHAIN_PATHS=/run/secrets/wallet-provider.pem,/run/secrets/intermediate.pem
```

If omitted, these default to `wallet-provider.key` and `wallet-provider.pem`
under `KEYS_DIR`. Production deployments should replace the file signer with a
non-exportable HSM/KMS-backed signer. Do not include the root trust anchor in
the `x5c` chain.

Optional lifecycle policy variables are:

```dotenv
WALLET_PROVIDER_KEY_ATTESTATION_TTL_SECONDS=900
WALLET_PROVIDER_STATUS_MAINTENANCE_SECONDS=2764800
WALLET_PROVIDER_MAX_STATUS_MAINTENANCE_SECONDS=31622400
WALLET_PROVIDER_STATUS_LIST_CAPACITY=10000
WALLET_PROVIDER_STATUS_LIST_TTL_SECONDS=300
```

The KA lifetime must remain below 24 hours. The default revocation maintenance
period is 32 days, and per-KA Status Lists contain at least 10,000 entries.

For local protocol testing only, the remote verifier can be replaced with the
explicitly unsafe development verifier:

```dotenv
DEV_WALLET_PROVIDER_ACCEPT_UNVERIFIED_EVIDENCE=true
DEV_WALLET_PROVIDER_KEY_STORAGE=iso_18045_high
DEV_WALLET_PROVIDER_USER_AUTHENTICATION=iso_18045_high
DEV_WALLET_PROVIDER_CERTIFICATION=https://example.invalid/development-only
```

These values do not prove the stated assurance. Every `DEV_*` variable is
rejected by the existing production startup guard.

A minimal authenticated development flow is:

```http
POST /wallet-provider/instances/activate
Content-Type: application/json

{
  "wallet_name": "wwWallet",
  "wallet_version": "development",
  "activation_evidence": {}
}
```

Then request a KA using the returned `wallet_instance_id`:

```http
POST /wallet-provider/key-attestations
Content-Type: application/json

{
  "wallet_instance_id": "<UUID>",
  "jwks": [{ "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }],
  "key_attestation_evidence": {},
  "proof_type": "jwt"
}
```

For the CS-04 `jwt` proof path, the issuer nonce belongs in the proof JWT and is
not accepted in the KA request. Set `proof_type` to `attestation` and supply
`openid4vci.nonce` only for the OpenID4VCI attestation-proof compatibility path.
The former `/wallet-provider/key-attestation/generate` path remains as a
deprecated alias but now enforces the same instance and evidence requirements.

## Pre-commit

We use [pre-commit](https://pre-commit.com/) to enforce our `.editorconfig` before code is committed.

### One-time setup

```
# install pre-commit if you don’t already have it
pip install pre-commit       # or brew install pre-commit / pipx install pre-commit

# enable the git hook in this repo
pre-commit install

# optional: clean up the repo on demand
pre-commit run --all-files

git add -A
```
### What happens on commit
- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, the editorconfig-checker runs inside Docker to validate all staged files.
- If violations remain, fix them manually until the commit passes.

# 2 Production

## 2.1. Preparation (The following steps should run on a clone of the production VM)

### 2.1.1. Configuration

1. Copy `config/config.template.ts` to `config/config.dev.ts`  and change it accordingly

2. Place the ssl keys on the ssl_keys/ directory

This directory must contain the following files

- `<server_name>-chain-only.pem`

- `<server_name>-server-only.pem`

- `<server_name>-server-with-chain.pem`

3. Change the server_name variable on the `entrypoint.sh` file

### 2.1.2. Install and Build for production

This step must run on a VM identical to the production system (same distribution, version and architecture)

```
yarn build:prod
```

Test the application

```
yarn start
```

### 2.1.3. Install 'paketo' globally and produce a snapshot

```
npm i -g @gsiou/paketo
yarn snapshot
```


### 2.1.4. Transfer the snapshot to the production server with rsync

```
rsync --rsh='ssh -p 65432' <snapshot_name>.tar.gz root@ip:/tmp
```

## 2.2. Deploy on the production server

```
cd /tmp
rm -rf wallet-backend
mkdir wallet-backend
tar -xf <snapshot_name>.tar.gz -C wallet-backend
cd wallet-backend
chmod +x entrypoint.sh
./entrypoint.sh
```

Add `Listen 9002` below the `Listen 443` line on `/etc/apache2/ports.conf`
and restart apache


## 💡Contributing
Want to contribute? Check out our [Contribution Guidelines](https://github.com/wwWallet/.github/blob/main/CONTRIBUTING.md) for more details!
