
var admin;
var serviceAccount;
try {
	admin = require("firebase-admin");
	serviceAccount = require(__dirname + '/../../../keys/ediplomas-wallet-firebase-adminsdk-1f8cq-d1fd260d2e.json');
	// const certPath = admin.credential.cert(serviceAccount);
	admin.initializeApp({
		credential: admin.credential.cert(serviceAccount),
		projectId: "ediplomas-wallet"
	});
}
catch(e) {
	console.error("Error: Notification capability is not enabled")
}


const sendPushNotification = async (fcm_token, title, body) => {
	try {
		let message = {
			notification: {
				title,
				body,
			},
			data: {
			},
			apns: {
				payload: {
					aps: {
						sound: 'default',
					},
				},
			},
			android: {
				notification: {
					sound: 'default',
				},
			},
			token: fcm_token,
		};
		admin.messaging().send(message)
			.then((response) => {
			console.log(response + ' messages were sent successfully');
			})
			.catch(err => {
				console.log("failed to send firebase message")
			});

	}
	catch(err) {
		throw err;
	}
}

export {
	sendPushNotification
}