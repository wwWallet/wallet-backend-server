# wwWallet Backend Server
wwWallet Backend Server is the backend of [wwWallet/wallet-frontend](https://github.com/wwWallet/wallet-frontend). It manages user accounts and WebAuthn passkeys, stores each user's encrypted wallet data, and provides helper services for the wallet like an HTTP proxy and an OHTTP relay.

> [!NOTE]
> To quickly setup the **wwWallet** ecosystem see https://github.com/wwWallet/wwwallet

## How to run

Install dependencies
```
yarn install
```

Create the configuration (see [Configuration](#configuration))
```
cp .env.template .env
```

Run database migrations (needs a running MariaDB/MySQL, see `DB_*` below)
```
yarn typeorm migration:run
```

Run in dev mode
```
yarn dev
```

## Configuration
Configuration is loaded from `.env` (see `.env.template`). Values are read via `dotenv` and validated in `config/index.ts`.

The server refuses to start if a required variable is missing or invalid. Empty values count as unset.

| Variable | Purpose | Default / Notes |
| --- | --- | --- |
| `PORT` | Port the server listens on. | **Required.** |
| `APP_URL` | Public URL of the server. | Only used in the startup log. Default: `http://localhost:$PORT`. |
| `APP_SECRET` | Secret used to sign session tokens. | **Required.** The `.env.template` value is for local development only and is refused when `NODE_ENV=production`; `yarn setup` in the parent repo generates a random one. Use a long random value in production. |
| `DB_HOST` | Database host (MariaDB/MySQL). | **Required.** |
| `DB_PORT` | Database port. | **Required.** |
| `DB_USER` | Database user. | **Required.** |
| `DB_PASSWORD` | Database password. | **Required.** |
| `DB_NAME` | Database name. | **Required.** |
| `WEBAUTHN_ORIGIN` | Origin(s) of the wallet frontend accepted in WebAuthn ceremonies. | **Required.** Comma-separated, e.g. `https://wallet.example.com`. |
| `WEBAUTHN_RP_ID` | WebAuthn Relying Party ID, usually the frontend's domain. | **Required.** e.g. `wallet.example.com`. |
| `WEBAUTHN_RP_NAME` | Relying Party name shown by authenticators. | Default: `wwWallet demo`. |
| `KEYS_DIR` | Directory with the wallet-provider keys: `wallet-provider.key`, `wallet-provider.pem` and `ca.pem`. | Default: `/app/keys` (Docker image layout). |
| `OHTTP_GATEWAY_URL` | Oblivious HTTP gateway that `/relay` forwards to. | Default: `http://localhost:4567`. |
| `METADATA_FIDO_URL` | FIDO Metadata Service used to identify authenticators. | Default: `https://c-mds.fidoalliance.org`. |
| `METADATA_COMMUNITY_AAGUID_URL` | Community list of passkey provider AAGUIDs. | Default: the [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids) list. |
| `METADATA_REFRESH_INTERVAL_MS` | How often authenticator metadata is refreshed (ms). | Default: `604800000` (7 days). |
| `REGISTRATION_DISABLED` | Set to `true` to disable new user registration (`/user/register`, `/user/register-webauthn-begin`, `/user/register-webauthn-finish`). | Default: `false`. Passkey management for existing users keeps working. |
| `DEBUG_ACCEPT_UNAUTHORIZED_HTTPS` | Set to `true` to accept invalid TLS certificates in `/proxy` and `/helper/get-cert`. | **Development only.** With `NODE_ENV=production`, the server refuses to start if any `DEBUG_*` variable is set. |

## Production

Build the Docker image from `Dockerfile` (version tags publish it as `ghcr.io/wwwallet/wallet-backend-server:<tag>`). To run it:

- Set the variables above as environment variables (at least the required ones).
- Mount the wallet-provider keys at `/app/keys` (or set `KEYS_DIR`).
- Run the migrations before starting a new version: `yarn migration:run:prod` inside the container.

## Pre-commit

We use [pre-commit](https://pre-commit.com/) to enforce our `.editorconfig` before code is committed.

#### One-time setup

```
# install pre-commit if you don’t already have it
pip install pre-commit       # or brew install pre-commit / pipx install pre-commit

# enable the git hook in this repo
pre-commit install

# optional: clean up the repo on demand
pre-commit run --all-files

git add -A
```

#### What happens on commit

- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, the editorconfig-checker runs inside Docker to validate all staged files.
- If violations remain, fix them manually until the commit passes.

## 💡Contributing
Want to contribute? Check out our [Contribution Guidelines](https://github.com/wwWallet/.github/blob/main/CONTRIBUTING.md) for more details!
