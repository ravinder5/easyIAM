import './App.css';
import React, { useState, useEffect } from 'react';
import { Grid, Button, Message, Form, Segment, Header } from 'semantic-ui-react';
import { getGetAssertionChallenge, getMakeCredentialsChallenge, sendWebAuthnResponse, sendWebAuthnAuthenticateResponse, getToken, getAuthCode, getProfile, logout, registerFail } from './webauthn';
import { preformatGetAssertReq, preformatMakeCredReq, publicKeyCredentialToJSON } from '../helpers';

function App() {
	const [errMsg, setErrMsg] = useState('');
	const [email, setEmail ] = useState('');
	const [requireResidentKey, setRequireResidentKey] = useState(true);
	const [successMsg, setSuccessMsg] = useState('');
	const [loggedIn, setLoggedIn] = useState(false);
	const [profileData, setProfileData] = useState(null);
	const [tokenData, setTokenData] = useState(null);

	const handleUsernameChange = (e) => {
		setEmail(e.target.value);
	};
	const handleRegister = () => {
		let requestIdFromServer = '';
		getMakeCredentialsChallenge({email, email, email, requireResidentKey})
			.then((response) => {
				console.log('start register response : ' + JSON.stringify(response));
				requestIdFromServer = response.requestId;
				console.log('RequestID From server : ' + requestIdFromServer);
				const publicKey = preformatMakeCredReq(response);
				console.log('public key : ' + publicKey);
				return navigator.credentials.create({ publicKey });
			})
			.then((response) => {
				console.log('before entering make:' + JSON.stringify(response));
				const makeCredResponse = publicKeyCredentialToJSON(response);
				console.log('makeCredResponse : ' + JSON.stringify(makeCredResponse));
				return sendWebAuthnResponse('https://localhost:8443/webauthn/register/finish', makeCredResponse, requestIdFromServer);
			})
			.then((response) => {
				if(response.success){
					setErrMsg('');
					setSuccessMsg('You can now try logging in');
				}
				else
					setErrMsg(response.message);
			})
			.catch(err => {
				if(err.response) {
					console.log('error message : ' + JSON.stringify(err.response.data.message));
					setErrMsg(err.response.data.message);
				}
				
				else
					console.log(err);
				// registerFail({email})
				// 	.then(() => {
				// 		if(err.response)
				// 			setErrMsg(err.response.data.message);
				// 		else
				// 			console.log(err);
				// 	});
			});
	};

	const handleLogin = () => {
		let requestIdFromServer = '';
		getGetAssertionChallenge({email})
			.then((response) => {
				requestIdFromServer = response.requestId;
				const publicKey = preformatGetAssertReq(response);
				return navigator.credentials.get({ publicKey });
			})
			.then((response) => {
				let getAssertionResponse = publicKeyCredentialToJSON(response);
				return sendWebAuthnAuthenticateResponse(getAssertionResponse, requestIdFromServer);
			})
			.then((response) => {
				return getAuthCode();
			})
			.then((response) => {
				if(response) {
					localStorage.setItem('loggedIn', true);
					localStorage.setItem('code', response);
					setLoggedIn(true);
					setEmail('');
					setSuccessMsg('');
					setErrMsg('');
					// setTokenData(response);
				} else {
					setSuccessMsg('');
					setErrMsg(response.message);
				}
			})
			.catch(err => {
				if(err.response)
					setErrMsg(err.response.data.message);
				else
					console.log(err);
			});
	};
	const handleLogout = () => {
		setEmail('');
		logout().then(() => {
			localStorage.removeItem('loggedIn');
			setLoggedIn(false);
			setProfileData(null);
			setTokenData(null);
		});
	};

	useEffect(() => {;
		if(localStorage.getItem('loggedIn'))
			setLoggedIn(true);
		if(loggedIn) {
			// const queryString = window.location.search;
			// const urlParams = new URLSearchParams(queryString);
			// const authCode = urlParams.get('code');
			const authCode = localStorage.getItem('code');
			getToken(authCode)
				.then(data => {
					setTokenData(data);
					localStorage.removeItem('code');
				})
				.catch(err => {
					setErrMsg(err.response.data.message);
					localStorage.removeItem('loggedIn');
					localStorage.removeItem('code');
				});
		}
			
	}, [loggedIn]);

	return (
		<div className='App-header'>
			<Grid container textAlign='center' verticalAlign='middle'>
				<Grid.Column style={{ maxWidth: 450, minWidth: 300 }}>
					<Header as='h2' textAlign='center' style={{ color: 'black'}}>
						WebAuthn Demo
					</Header>
					{!loggedIn ?
						<Form size='large'>
							{errMsg && <Message negative icon='warning sign' size='mini' header={errMsg}/>}
							{successMsg && <Message positive icon='thumbs up' size='mini' header={successMsg}/>}
							<Segment>
								<Form.Input 
									fluid
									icon='user'
									iconPosition='left'
									placeholder='Username'
									onChange={handleUsernameChange}
								/>
								<Button 
									fluid 
									size='large' 
									onClick={handleRegister} 
									style={{ 
										marginTop: 8,
										color: 'white',
										backgroundColor: '#19857b'
									}}
									disabled={!email}
								>
									Register
								</Button>
								<Button 
									fluid 
									size='large'
									onClick={handleLogin} 
									style={{ 
										marginTop: 8,
										color: 'white',
										backgroundColor: '#19857b'
									}}
									disabled={!email}
								>
									Login
								</Button>
							</Segment>
						</Form>
						:
						<Segment style={{ overflowWrap: 'break-word'}}>
							{tokenData &&
								<>
									<Header as='h3' textAlign='center'>
										Hi
									</Header>
									<Header as='h4' textAlign='center'>
										Your Token information
									</Header>
									<strong>AccessToken: </strong>{tokenData.access_token}
									<br/>
									<strong>TokenType: </strong>{tokenData.token_type}
									<br/>
									<strong>Expires In: </strong>{tokenData.expires_in}
									<br/>
									<strong>RefreshToken: </strong>{tokenData.refresh_token}
									<br/>
									<strong>Scope: </strong>{tokenData.scope}
									<br/>
									<div style={{
										maxWidth: 300,
										overflowWrap: 'break-word',
										marginLeft: '25%',
										marginRight: '25%'
									}}>
									</div>
									<Button 
										fluid 
										size='large'
										onClick={handleLogout} 
										style={{ 
											marginTop: 8,
											color: 'white',
											backgroundColor: '#19857b'
										}}
									>
										Logout
									</Button>
								</>
							}
						</Segment>
					}
				</Grid.Column>
			</Grid>
		</div>
	);
}

export default App;
