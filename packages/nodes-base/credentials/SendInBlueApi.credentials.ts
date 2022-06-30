// eslint-disable-next-line n8n-nodes-base/filesystem-wrong-cred-filename
import {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class SendInBlueApi implements ICredentialType {
	name = 'sendinblueApi';
	displayName = 'SendInBlue API';
	documentationUrl = 'sendinblue';
	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			default: '',
		},
	];
	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				'api-key': '={{$credentials.apiKey}}',
			},
		},
	};
	test: ICredentialTestRequest = {
		request: {
			baseURL: 'https://api.sendinblue.com/v3',
			url: '/account',
		},
	};
}
