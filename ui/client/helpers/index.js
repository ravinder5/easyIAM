import base64url from './base64url-arraybuffer';

function publicKeyCredentialToJSON(pubKeyCred) {
	console.log('public key cred : ' + JSON.stringify(pubKeyCred));
	let clientExtensionResults = {};

	try {
	  clientExtensionResults = pubKeyCred.getClientExtensionResults();
	} catch (e) {
	  console.error('getClientExtensionResults failed', e);
	}

	if (pubKeyCred.response.attestationObject) {
		console.log('attestationObject : ' + pubKeyCred.response.attestationObject);
	  return {
			type: pubKeyCred.type,
			id: pubKeyCred.id,
			response: {
		  		attestationObject: mimeBase64ToUrl(base64url.fromByteArray(new Uint8Array(pubKeyCred.response.attestationObject))),
		  		clientDataJSON: mimeBase64ToUrl(base64url.fromByteArray(new Uint8Array(pubKeyCred.response.clientDataJSON))),
			},
			clientExtensionResults
	  	};
	} else {
	  return {
			type: pubKeyCred.type,
			id: pubKeyCred.id,
			response: {
		  		authenticatorData: mimeBase64ToUrl(base64url.fromByteArray(new Uint8Array(pubKeyCred.response.authenticatorData))),
		  		clientDataJSON: mimeBase64ToUrl(base64url.fromByteArray(new Uint8Array(pubKeyCred.response.clientDataJSON))),
		  		signature: mimeBase64ToUrl(base64url.fromByteArray(new Uint8Array(pubKeyCred.response.signature))),
		  		userHandle: pubKeyCred.response.userHandle && mimeBase64ToUrl(base64url.fromByteArray(new Uint8Array(pubKeyCred.response.userHandle))),
			},
			clientExtensionResults
	  };
	}


	// if (pubKeyCred instanceof Array) {
	// 	let arr = [];
	// 	for (let i of pubKeyCred) arr.push(publicKeyCredentialToJSON(i));

	// 	return arr;
	// }

	// else if (pubKeyCred instanceof ArrayBuffer) {
	// 	return base64url.encode(pubKeyCred);
	// }

	// else if (pubKeyCred instanceof Object) {
	// 	let obj = {};

	// 	for (let key in pubKeyCred) {
	// 		obj[key] = publicKeyCredentialToJSON(pubKeyCred[key]);
	// 	}

	// 	return obj;
	// }

	// return pubKeyCred;
}

function generateRandomBuffer(len) {
	len = len || 32;

	const randomBuffer = new Uint8Array(len);
	window.crypto.getRandomValues(randomBuffer);

	return randomBuffer;
}

let  preformatMakeCredReq = (makeCredReq) => {
	// const excludeCredentials = makeCredReq.publicKeyCredentialCreationOptions.excludeCredentials.map(credential => extend(credential, {id: base64url.toByteArray(credential.id),}));
	let excludeCredentials = [];

	const request = makeCredReq.publicKeyCredentialCreationOptions;
	console.log('before decode');
	const publicKeyCredentialCreationOptions = extend(
		request, {
			attestation: 'direct',
			user: extend(
				request.user, {
					id: base64url.toByteArray(base64UrlToMime(request.user.id)),
				}
			),
			challenge: base64url.toByteArray(base64UrlToMime(request.challenge)),
			excludeCredentials,
		}
	);
	console.log('after decode : ' + JSON.stringify(publicKeyCredentialCreationOptions));
	return publicKeyCredentialCreationOptions;
};

function base64UrlToMime(code) {
	return code.replace(/-/g, '+').replace(/_/g, '/') + '===='.substring(0, (4 - (code.length % 4)) % 4);
}

function mimeBase64ToUrl(code) {
	return code.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function extend(obj, more) {
	return Object.assign({}, obj, more);
}

let preformatGetAssertReq = (getAssert) => {
	console.log('getAssert : ' + JSON.stringify(getAssert));
	let excludeCredentials = [];
	const allowCredentials = getAssert.publicKeyCredentialRequestOptions.allowCredentials && getAssert.publicKeyCredentialRequestOptions.allowCredentials.map(credential => extend(credential, {id: base64url.toByteArray(base64UrlToMime(credential.id)),}));

	const request = getAssert.publicKeyCredentialRequestOptions;
	console.log('AUthenticate before decode');
	const publicKeyCredentialRequestOptions = extend(
		request, {
			allowCredentials,
			challenge: base64url.toByteArray(base64UrlToMime(request.challenge)),
		}
	);
	console.log('Authenticate after decode : ' + JSON.stringify(publicKeyCredentialRequestOptions));
	return publicKeyCredentialRequestOptions;
	// getAssert.challenge = base64url.decode(getAssert.challenge);
    
	// for(let allowCred of getAssert.allowCredentials) {
	// 	allowCred.id = base64url.decode(allowCred.id);
	// }

	// return getAssert;
};

export { publicKeyCredentialToJSON, generateRandomBuffer, preformatGetAssertReq, preformatMakeCredReq };
