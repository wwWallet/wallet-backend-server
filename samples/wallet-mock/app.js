var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const { trustedIssuerDID, walletBackendUrl, uoaTrustedIssuerDID, vidTrustedIssuerDID } = require('./config')

const { registerUser } = require('./lib');
var app = express();
const axios = require('axios');
const { default: base64url } = require('base64url');
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');


app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


global.user = {
	did: "",
	appToken: ""
}


app.use(async (req, res, next) => {
	console.log("did = ", req.cookies["did"] == undefined)
	if (global.user.did == "") {
		await registerUser();

	}
	next();
})


app.use(handleCredentialOffer);
app.use(handleAuthorizationResponse);
app.use(handleAuthorizationRequest);



app.get('/', async (req, res) => {
	axios.get(walletBackendUrl + '/storage/vc',
		{ headers: { "Authorization": `Bearer ${global.user.appToken}` }}
	).then(response => {
		let { vc_list } = response.data;
		console.log("VC list = ");

		console.dir(vc_list);
		vc_list = vc_list.map((vc) => {
			const vcjwt = vc.credential;
			const payload = JSON.parse(base64url.decode(vcjwt.split('.')[1]));
			return payload;
		})

		res.render('index', {
			vc_list: vc_list
		})
	}).catch(e => {
		console.log("Failed to render")
		if (e.response) {
			console.error("Error response = ", e.response.data)
		}
		res.status(500).send()
	})
})

app.get('/vp', async (req, res) => {
	axios.get(walletBackendUrl + '/storage/vp',
		{ headers: { "Authorization": `Bearer ${global.user.appToken}` }}
	).then(response => {
		let { vp_list } = response.data;
		console.log("VP list = ");

		console.dir(vp_list);
		vp_list = vp_list.map((vp) => {
			const vpjwt = vp.presentation;
			const payload = JSON.parse(base64url.decode(vpjwt.split('.')[1]));
			return payload;
		})
	

		res.render('presentations', {
			vp_list: vp_list
		})
	}).catch(e => {
		console.log("Failed to render")
		console.log("err")
		console.log("Error response = ", e.response.data)
		res.status(500).send()
	})
})

app.get('/vc/:vc_id', async (req, res) => {
	const vc_id = req.params.vc_id;
	axios.get(walletBackendUrl + '/storage/vc/'+vc_id,
		{ headers: { "Authorization": `Bearer ${global.user.appToken}` }}
	).then(response => {
		let vc = response.data;
		console.log("VC list = ");

		const vcjwt = vc.credential;
		const payload = base64url.decode(vcjwt.split('.')[1]);

		res.render('vc', {
			title: "Wallet Mock",
			vc: payload
		})
	}).catch(e => {
		console.log("Failed to render")
		console.error(e)
		res.status(500).send()
	})
})

app.get('/vp/:vp_id', async (req, res) => {
	const vp_id = req.params.vp_id;
	axios.get(walletBackendUrl + '/storage/vp/'+vp_id,
		{ headers: { "Authorization": `Bearer ${global.user.appToken}` }}
	).then(response => {
		let vp = response.data;
		console.log("VP = ");
		console.dir(vp, { depth: null})
		const vpjwt = vp.presentation;
		const payload = base64url.decode(vpjwt.split('.')[1]);
		
		res.render('vc', {
			title: "Wallet Mock",
			vc: payload
		})
	}).catch(e => {
		console.log("Failed to render")
		console.error(e)
		res.status(500).send()
	})
})



// Issuance initiation (Send Authorization Request)
app.get('/init/issuance/:iss', async (req, res) => {
	const iss = req.params.iss;
	console.log("first get")
	console.log("User = ", user)
	const selectedIssuerDID = iss == 'vid' ? vidTrustedIssuerDID : uoaTrustedIssuerDID;

	try {
		const issuanceInitiation = await axios.post(walletBackendUrl + '/issuance/generate/authorization/request', 
			{ legal_person_did: selectedIssuerDID },
			{ headers: { "Authorization": `Bearer ${global.user.appToken}` }}
		);
		const { redirect_to } = issuanceInitiation.data;
		res.redirect(redirect_to);
	}
	catch(e) {
		console.error("Failed to send initiation. Issuer possibly does not exist on the local registry");
		return res.status(500).send({ msg: "Failed to send initiation. Issuer possibly does not exist on the local registry" });
	}

});



/**
 * For OpenID 4 VCI (Issuance)
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
async function handleCredentialOffer(req, res, next) {
	const url = `${req.protocol}://${req.hostname}${req.originalUrl}`;

	axios.post(walletBackendUrl + "/issuance/generate/authorization/request/with/offer",
		{ credential_offer_url: url },
		{ headers: { "Authorization": `Bearer ${global.user.appToken}` }}
	).then(success => {
		console.log("SUccess = ", success.data)
		const { redirect_to } = issuanceInitiation.data;
		return res.redirect(redirect_to);
	}).catch(e => {
		next();
	})
}

/**
 * For OpenID 4 VCI (Issuance)
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
async function handleAuthorizationResponse(req, res, next) {
  const url = `${req.protocol}://${req.hostname}${req.originalUrl}`;

	axios.post(walletBackendUrl + "/issuance/handle/authorization/response",
		{ authorization_response_url: url },
		{ headers: { "Authorization": `Bearer ${global.user.appToken}` }}
	).then(success => {
		console.log("SUccess = ", success.data)
		res.redirect('/');
	}).catch(e => {
		next();
	})
}



/**
 * For OpenID 4 VP (Verification)
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
async function handleAuthorizationRequest(req, res, next) {
  const url = `${req.protocol}://${req.hostname}${req.originalUrl}`;
	console.log("URL = ", url)
	axios.post(walletBackendUrl + "/presentation/handle/authorization/request",
		{ authorization_request: url },
		{ headers: { "Authorization": `Bearer ${global.user.appToken}` }}
	).then(success => {
		console.log("Success")
		const { conformantCredentialsMap, verifierDomainName } = success.data;
		return res.render('select-vc', {
			title: "VC Selection",
			conformantCredentialsMap: conformantCredentialsMap
		})
	}).catch(e => {
		console.log("Failed")
		next();
	});

}


app.post('/select-vc', async (req, res) => {
	console.log("Req = ", req.body)
	axios.post(walletBackendUrl + "/presentation/generate/authorization/response",
			{ verifiable_credentials_map: req.body },
			{ headers: { "Authorization": `Bearer ${global.user.appToken}` }}
		).then(success => {
			const { redirect_to } = success.data;
			res.redirect(redirect_to);
		}).catch(e => {
			// console.error("Failed to generate authorization response")
			// console.error(e.response.data);
			res.render('error', { title: "Error", error: { status: 500 } })
		});
})

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});


// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

console.log("Started wallet mock server...")

module.exports = app;
