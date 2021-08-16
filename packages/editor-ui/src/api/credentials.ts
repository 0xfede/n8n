import { ICredentialsDecryptedResponse, ICredentialsResponse, IRestApiContext } from '@/Interface';
import { makeRestApiRequest } from './helpers';
import {
	ICredentialsDecrypted,
	ICredentialType,
	IDataObject,
} from 'n8n-workflow';

export async function getCredentialTypes(context: IRestApiContext): Promise<ICredentialType[]> {
	return await makeRestApiRequest(context, 'GET', '/credential-types');
}

export async function getCredentialsNewName(context: IRestApiContext, name?: string): Promise<{name: string}> {
	return await makeRestApiRequest(context, 'GET', '/credentials/new', name ? { name } : {});
}

export async function getAllCredentials(context: IRestApiContext): Promise<ICredentialType[]> {
	return await makeRestApiRequest(context, 'GET', '/credentials');
}

export async function createNewCredential(context: IRestApiContext, data: ICredentialsDecrypted): Promise<ICredentialsResponse> {
	return makeRestApiRequest(context, 'POST', `/credentials`, data as unknown as IDataObject);
}

export async function deleteCredential(context: IRestApiContext, id: string): Promise<Boolean> {
	return makeRestApiRequest(context, 'DELETE', `/credentials/${id}`);
}

export async function updateCredential(context: IRestApiContext, params: {data: ICredentialsDecrypted, id: number}): Promise<ICredentialsResponse> {
	const { id } = params;
	return makeRestApiRequest(context, 'PATCH', `/credentials/${id}`, params.data as unknown as IDataObject);
}

export async function getCredentialData(context: IRestApiContext, id: string): Promise<ICredentialsDecryptedResponse | ICredentialsResponse | undefined> {
	return makeRestApiRequest(context, 'GET', `/credentials/${id}`, {
		includeData: true,
	});
}

// // Get OAuth1 Authorization URL using the stored credentials
// export async function oAuth1CredentialAuthorize(context: IRestApiContext, sendData: ICredentialsResponse): Promise<string> {
// 	return makeRestApiRequest(context, 'GET', `/oauth1-credential/auth`, sendData);
// }

// // Get OAuth2 Authorization URL using the stored credentials
// export async function oAuth2CredentialAuthorize(context: IRestApiContext, sendData: ICredentialsResponse): Promise<string> {
// 	return makeRestApiRequest(context, 'GET', `/oauth2-credential/auth`, sendData);
// }

// // Verify OAuth2 provider callback and kick off token generation
// export async function oAuth2Callback(context: IRestApiContext, code: string, state: string): Promise<string> {
// 	const sendData = {
// 		'code': code,
// 		'state': state,
// 	};

// 	return makeRestApiRequest(context, 'POST', `/oauth2-credential/callback`, sendData);
// }
