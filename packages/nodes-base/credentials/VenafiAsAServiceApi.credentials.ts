import {
	ICredentialType,
	NodePropertyTypes,
} from 'n8n-workflow';

export class VenafiAsAServiceApi implements ICredentialType {
	name = 'venafiAsAServiceApi';
	displayName = 'Venafi As a Service API';
	properties = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string' as NodePropertyTypes,
			default: '',
		},
	];
}
