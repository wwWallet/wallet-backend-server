#!/usr/bin/env node


"use strict";
const yargs = require('yargs');
require('dotenv').config();
const knex = require('knex');
const { NaturalPersonWallet } = require('@wwWallet/ssi-sdk')
const crypto = require('node:crypto');

const db = knex({
  client: 'mysql2',
  connection: {
    // Database connection details
    // For example:
    host: process.env.DB_HOST,
		port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  }
});

yargs
  .command('create', '', (createYargs) => {
		createYargs
			.command('did', 'Create did', (didArgs) => {
				didArgs
					.option('username', {
						description: "Give client id",
						type: "string",
						demandOption: true,
						alias: 'n'
					})
					.option('password', {
						description: "Give client secret",
						type: "string",
						demandOption: true,
						alias: 'p'
					})
					createUser({...didArgs.argv})
			})
			.command('issuer', 'Create issuer', (createIssuerArgs) => {
				createIssuerArgs
					.option('friendlyName', {
						description: "Give friendlyName",
						type: "string",
						demandOption: true,
					})
					.option('url', {
						description: "Give url",
						type: "string",
						demandOption: true,
					})
					.option('did', {
						description: "Give url",
						type: "string",
						demandOption: true,
					})
					.option('client_id', {
						description: "Give client_id",
						type: "string",
						demandOption: true,
					})
					createIssuer({...createIssuerArgs.argv})
			})
  })
  .help()
  .argv;



async function createUser({username, password}) {

	const passwordHash = crypto.createHash('sha256').update(password).digest('base64');

	const w = await new NaturalPersonWallet().createWallet('ES256');
	const did = w.key.did;
	const keys = JSON.stringify(w.key);
	const fcmToken = "";
	const isAdmin = 1;
	db("user")
  .insert({username, passwordHash, did, keys, fcmToken, isAdmin})
  .then((result) => {
    // Process the insertion result
		console.log(`Wallet provider DID:\t${did}`)
		return;
  })
  .catch((error) => {
		db.select("*")
			.from("user")
			.where('username' , '=', username)
			.then(rows => {
				const first = rows.length ? rows[0] : null;
				if (first) {
					console.log(`Wallet provider already exists with DID:\t${first.did}`)
				}
			})
			.catch(e => {
				console.log(e)
			})
			.finally(() => {
				db.destroy();
			})
    // Handle insertion errors`
    console.error('Error inserting new row');

  })
	.finally(() => {
		db.destroy();
	});
	return;
}

async function createIssuer({friendlyName, url, did, client_id}) {
	try {
		const rows = await db.select("*")
					.from("legal_person")
					.where('did' , '=', did);
		if (rows.length > 0) {
			console.log(`Legal person already exists with DID:\t${did}`)
			db.destroy();
			return;
		}
	} catch (e) {
		console.log(e);
		db.destroy();
		return;
	}

	db("legal_person")
  .insert({friendlyName, url, did, client_id})
  .then((result) => {
    // Process the insertion result
    console.log('New legal person inserted successfully');
		db.destroy()
		return;
  })
  .catch((error) => {
    // Handle insertion errors
    console.error('Error inserting new row:', error);
		db.destroy()

  });
	return;
}