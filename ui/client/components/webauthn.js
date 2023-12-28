import axios from 'axios';
axios.defaults.withCredentials = true;

function getMakeCredentialsChallenge(formBody){
	const params = new URLSearchParams({
		username: formBody.email,
		displayName: formBody.email,
		credentialNickname: formBody.email,
    	requireResidentKey: true
	  }).toString();
	return axios.post('https://localhost:8443/webauthn/register?' + params, formBody)
		.then(response => {
			if (response.status != 200) 
				throw new Error(`Server responed with error. The message is: ${response.data.message}`);
			return response.data;
		});
}

function sendWebAuthnResponse(url, body, requestId){
	const requestBody = {
		requestId,
		credential: body
	};
	return axios.post(url, requestBody)
		.then(response => {
			if(response.status != 200)
				throw new Error(`Server responed with error. The message is: ${response.data.message}`);
			return response.data;
		});
}
function sendWebAuthnAuthenticateResponse(body, requestId){
	const requestBody = {
		requestId,
		credential: body
	};
	return axios.post('https://localhost:8443/webauthn/authenticate/finish', requestBody)
		.then(response => {
			if(response.status != 200)
				throw new Error(`Server responed with error. The message is: ${response.data.message}`);
			return response.data;
		});
}

function getGetAssertionChallenge (formBody){
	const params = new URLSearchParams({
		username: formBody.email,
		displayName: formBody.email,
		credentialNickname: formBody.email,
    	requireResidentKey: true
	  }).toString();
	return axios.post('https://localhost:8443/webauthn/authenticate?' + params, formBody)
		.then(response => {
			if (response.status != 200) 
				throw new Error(`Server responed with error. The message is: ${response.data.message}`);
			return response.data;
		});
};

function getProfile() {
	return axios.get('webauthn/profile')
		.then(response => response.data);
}

function getAuthCode() {
	return axios.get('https://localhost:8443/auth/authenticate?response_type=code&client_id=test-1.0.0&redirect_uri=https://localhost:3000&scope=iam.admin&state=12345')
		.then(response => response.data);
}

function getToken(authCode) {
	const requestBody = {
		grant_type: 'authorization_code',
		code: authCode,
		client_id: 'test-1.0.0',
		client_secret: 'password'
	};
	return axios.post('https://localhost:8443/auth/tokens', requestBody)
		.then(response => response.data);
}

function logout() {
	return axios.post('https://localhost:8443/auth/authenticate/reauth')
		.then(response => response.data);
}
function registerFail(body){
	return axios.post ('webauthn/registerfail', body)
		.then(response => response.data);
}
export {
	getGetAssertionChallenge,
	getMakeCredentialsChallenge,
	sendWebAuthnResponse,
	sendWebAuthnAuthenticateResponse,
	getToken,
	getAuthCode,
	getProfile,
	logout,
	registerFail
};
