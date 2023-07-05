const axios = require('axios');
const { randomUUID } = require('crypto');
const { walletBackendUrl } = require('./config');

async function registerUser() {
	try {
		const result = await axios.post(walletBackendUrl + "/user/register", {
			username: randomUUID(),
			password: randomUUID()
		})
		const { did, appToken } = result.data
		global.user = { did, appToken }
		console.log("New user = ", global.user)
	}
	catch(e) {
		console.error("Failed to register user")
		return
	}

}

module.exports = {
	registerUser
}