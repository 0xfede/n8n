import {
	OptionsWithUri,
} from 'request';

import {
	IExecuteFunctions,
} from 'n8n-core';

import {
	IDataObject,
	NodeApiError,
} from 'n8n-workflow';

import {
	ElasticSearchApiCredentials,
} from './types';

export async function elasticSearchApiRequest(
	this: IExecuteFunctions,
	method: 'GET' | 'PUT' | 'POST' | 'DELETE',
	endpoint: string,
	body: IDataObject = {},
	qs: IDataObject = {},
) {
	const {
		username,
		password,
		baseUrl,
	} = this.getCredentials('elasticSearchApi') as ElasticSearchApiCredentials;

	const token = Buffer.from(`${username}:${password}`).toString('base64');

	const options: OptionsWithUri = {
		headers: {
			Authorization: `Basic ${token}`,
			'Content-Type': 'application/json',
		},
		method,
		body,
		qs,
		uri: `${baseUrl}${endpoint}`,
		json: true,
	};

	if (!Object.keys(body).length) {
		delete options.body;
	}

	if (!Object.keys(qs).length) {
		delete options.qs;
	}

	try {
		console.log(options);
		return await this.helpers.request(options);
	} catch (error) {
		throw new NodeApiError(this.getNode(), error);
	}
}
