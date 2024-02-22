import type { INodeProperties } from 'n8n-workflow';
import { SQL_PREFIX, SQL_SUFFIX } from './other/prompts';

const dataSourceOptions: INodeProperties = {
	displayName: 'Data Source',
	name: 'dataSource',
	type: 'options',
	displayOptions: {
		show: {
			agent: ['sqlAgent'],
		},
	},
	default: 'sqlite',
	description: 'SQL database to connect to',
	options: [
		{
			name: 'MySQL',
			value: 'mysql',
			description: 'Connect to a MySQL database',
		},
		{
			name: 'Postgres',
			value: 'postgres',
			description: 'Connect to a Postgres database',
		},
		{
			name: 'SQLite',
			value: 'sqlite',
			description: 'Use SQLite by connecting a database file as binary input',
		},
	],
};

export const sqlAgentAgentProperties: INodeProperties[] = [
	{
		...dataSourceOptions,
		displayOptions: {
			show: {
				agent: ['sqlAgent'],
				'@version': [{ _cnd: { lt: 1.4 } }],
			},
		},
	},
	{
		...dataSourceOptions,
		default: 'postgres',
		displayOptions: {
			show: {
				agent: ['sqlAgent'],
				'@version': [{ _cnd: { gte: 1.4 } }],
			},
		},
	},
	{
		displayName: 'Credentials',
		name: 'credentials',
		type: 'credentials',
		default: '',
	},
	{
		// eslint-disable-next-line n8n-nodes-base/node-param-display-name-miscased
		displayName:
			"Input item has to contain sqLite file as a binary, e.g. use 'Read/Write Files from Disk' node and combine it with 'Chat' input by 'Edit Fields' node",
		name: 'sqLiteFileNotice',
		type: 'notice',
		default: '',
		displayOptions: {
			show: {
				agent: ['sqlAgent'],
				dataSource: ['sqlite'],
			},
		},
	},
	{
		displayName: 'Prompt',
		name: 'input',
		type: 'string',
		displayOptions: {
			show: {
				agent: ['sqlAgent'],
				'@version': [{ _cnd: { lte: 1.2 } }],
			},
		},
		default: '',
		required: true,
		typeOptions: {
			rows: 5,
		},
	},
	{
		displayName: 'Prompt',
		name: 'promptType',
		type: 'options',
		options: [
			{
				// eslint-disable-next-line n8n-nodes-base/node-param-display-name-miscased
				name: 'Take from previous node automatically',
				value: 'auto',
				description: 'Looks for an input field called chatInput',
			},
			{
				// eslint-disable-next-line n8n-nodes-base/node-param-display-name-miscased
				name: 'Define below',
				value: 'define',
				description: 'Use an expression to reference data in previous nodes or enter static text',
			},
		],
		displayOptions: {
			hide: {
				'@version': [{ _cnd: { lte: 1.2 } }],
			},
			show: {
				agent: ['sqlAgent'],
			},
		},
		default: 'auto',
	},
	{
		displayName: 'Text',
		name: 'text',
		type: 'string',
		required: true,
		default: '',
		placeholder: 'e.g. Hello, how can you help me?',
		typeOptions: {
			rows: 2,
		},
		displayOptions: {
			show: {
				promptType: ['define'],
				agent: ['sqlAgent'],
			},
		},
	},
	{
		displayName: 'Options',
		name: 'options',
		type: 'collection',
		displayOptions: {
			show: {
				agent: ['sqlAgent'],
			},
		},
		default: {},
		placeholder: 'Add Option',
		options: [
			{
				displayName: 'Ignored Tables',
				name: 'ignoredTables',
				type: 'string',
				default: '',
				description:
					'Comma-separated list of tables to ignore from the database. If empty, no tables are ignored.',
			},
			{
				displayName: 'Include Sample Rows',
				name: 'includedSampleRows',
				type: 'number',
				description:
					'Number of sample rows to include in the prompt to the agent. It helps the agent to understand the schema of the database but it also increases the amount of tokens used.',
				default: 3,
			},
			{
				displayName: 'Included Tables',
				name: 'includedTables',
				type: 'string',
				default: '',
				description:
					'Comma-separated list of tables to include in the database. If empty, all tables are included.',
			},
			{
				displayName: 'Prefix Prompt',
				name: 'prefixPrompt',
				type: 'string',
				default: SQL_PREFIX,
				description: 'Prefix prompt to use for the agent',
				typeOptions: {
					rows: 10,
				},
			},
			{
				displayName: 'Suffix Prompt',
				name: 'suffixPrompt',
				type: 'string',
				default: SQL_SUFFIX,
				description: 'Suffix prompt to use for the agent',
				typeOptions: {
					rows: 4,
				},
			},
			{
				displayName: 'Limit',
				name: 'topK',
				type: 'number',
				default: 10,
				description: 'The maximum number of results to return',
			},
		],
	},
];
