
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


## Working with database migrations

The app runs database migrations from `/src/migrations` on startup, and when the application is reloaded in the dev server.
Unfortunately, compiled migrations remain in the output directory even after you check out an older version,
so you have to delete the output files manually.

To check out an earlier version:

 1. Delete migrations from the compilation output directory: `docker-compose exec wallet-backend-server rm -r dist/src/migrations`
 2. Kill the docker-compose environment: `docker-compose stop`
 3. Restart the database container: `docker-compose start wallet-db`
 4. Revert migrations until you're at the database state of the target commit (or earlier):
    - `npm run typeorm -- migration:show` to show current migration state
    - `npm run typeorm -- migration:revert` to move backward one migration at a time
    - `npm run typeorm -- migration:run` to move forward one migration at a time
 5. Check out the targeted earlier commit.

To show the diff between the database and the current TypeORM state:

```sh
$ npm run typeorm -- schema:log
```

To generate a migration for the diff between the database and the current TypeORM state:

```sh
$ npm run typeorm -- migration:generate src/migrations/<name of new migration script>
```

While working with migrations it's usually best to stop the development server (`docker-compose stop wallet-backend-server`) first,
otherwise the dev server will attempt to run migrations immediately when the app reloads.


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

# 3 Logging


