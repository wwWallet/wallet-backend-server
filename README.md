
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