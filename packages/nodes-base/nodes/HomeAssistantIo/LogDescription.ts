import { INodeProperties } from 'n8n-workflow';

export const logOperations = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		displayOptions: {
			show: {
				resource: [
					'log',
				],
			},
		},
		options: [
			{
				name: 'Get Error Logs',
				value: 'getErroLogs',
				description: 'Get a log for a specific entity',
			},
			{
				name: 'Get Logbook Entries',
				value: 'getLogbookEntries',
				description: 'Get all logs',
			},
		],
		default: 'get',
		description: 'The operation to perform.',
	},
] as INodeProperties[];

export const logFields = [
	/* -------------------------------------------------------------------------- */
	/*                                log:getLogbookEntries                       */
	/* -------------------------------------------------------------------------- */
	{
		displayName: 'Additional Fields',
		name: 'additionalFields',
		type: 'collection',
		placeholder: 'Add Field',
		default: {},
		displayOptions: {
			show: {
				resource: [
					'log',
				],
				operation: [
					'getLogbookEntries',
				],
			},
		},
		options: [
			{
				displayName: 'Start Time',
				name: 'startTime',
				type: 'dateTime',
				default: '',
				description: 'The beginning of the period.',
			},
			{
				displayName: 'Entity ID',
				name: 'entityId',
				type: 'string',
				default: '',
				description: 'The entity ID.',
			},
			{
				displayName: 'End Time',
				name: 'endTime',
				type: 'dateTime',
				default: '',
				description: 'The end of the period.',
			},
		],
	},
] as INodeProperties[];
