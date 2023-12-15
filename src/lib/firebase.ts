
var admin;
var serviceAccount;
var path = require('path');
const config = require('../../config').default;

if (config.notifications.enabled) {
	try {
		admin = require("firebase-admin");
		serviceAccount = path.join('/', 'app', 'keys', config.notifications.serviceAccount)
		// const certPath = admin.credential.cert(serviceAccount);
		admin.initializeApp({
			credential: admin.credential.cert(serviceAccount),
			projectId: serviceAccount.project_id
		});
		console.log("Notification capability is enabled")
	}
	catch (e) {
		console.log(e)
		console.error("Error: Notification capability is not enabled")
	}
} else {
	console.log("Notification capability is not enabled")
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