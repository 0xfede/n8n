import { INodeProperties } from 'n8n-workflow';

export const emailOperations: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: {
			show: {
				resource: [
					'email',
				],
			},
		},
		options: [
			{
				name: 'Send',
				value: 'send',
			},
			{
				name: 'Send Template',
				value: 'sendTemplate',
			},
		],
		routing: {
			request: {
				method: 'POST',
				url: '/v3/smtp/email',
			},
		},
		default: 'send',
	},
];

const emailAttachments: INodeProperties[] = [
	{
		displayName: 'Attachments',
		default: {},
		name: 'emailAttachments',
		type: 'fixedCollection',
	},
];

const sendHtmlEmailFields: INodeProperties[] = [
	{
		displayName: 'Subject',
		name: 'subject',
		type: 'string',
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'send',
				],
			},
		},
		routing: {
			send: {
				property: 'subject',
				type: 'body',
			},
		},
		default: '',
		description: 'Subject of the email',
	},
	{
		displayName: 'Send HTML',
		name: 'sendHTML',
		type: 'boolean',
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'send',
				],
			},
		},
		default: false,
	},
	{
		displayName: 'Text Content',
		name: 'textContent',
		type: 'string',
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'send',
				],
				sendHTML: [
					false,
				],
			},
		},
		routing: {
			send: {
				property: 'textContent',
				type: 'body',
			},
		},
		default: '',
		description: 'Text content of the message',
	},
	{
		displayName: 'HTML Content',
		name: 'htmlContent',
		type: 'string',
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'send',
				],
				sendHTML: [
					true,
				],
			},
		},
		routing: {
			send: {
				property: 'htmlContent',
				type: 'body',
			},
		},
		default: '',
		description: 'HTML content of the message',
	},
	{
		displayName: 'Sender',
		name: 'sender',
		placeholder: 'Add Sender',
		required: true,
		type: 'fixedCollection',
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'send',
				],
			},
		},
		default: {},
		options: [
			{
				name: 'sender',
				displayName: 'Sender',
				values: [
					{
						displayName: 'Name',
						name: 'name',
						type: 'string',
						default: '',
						routing: {
							send: {
								property: '=sender.name',
								type: 'body',
							},
						},
						description: 'Name of the sender',
					},
					{
						displayName: 'Email',
						name: 'email',
						type: 'string',
						default: '',
						routing: {
							send: {
								property: '=sender.email',
								type: 'body',
							},
						},
						description: 'Email of the sender',
					},
				],
				required: true,
			},
		],
	},
	{
		displayName: 'Receipients',
		name: 'receipients',
		placeholder: 'Add Receipient',
		type: 'fixedCollection',
		typeOptions: {
			multipleValues: true,
		},
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'send',
				],
			},
		},
		default: {},
		options: [
			{
				name: 'receipient',
				displayName: 'Receipient',
				values: [
					{
						displayName: 'Name',
						name: 'name',
						type: 'string',
						default: '',
						routing: {
							send: {
								property: '=to[{{$index}}].name',
								type: 'body',
							},
						},
						description: 'Name of the receipient',
					},
					{
						displayName: 'Email',
						name: 'email',
						type: 'string',
						default: '',
						routing: {
							send: {
								property: '=to[{{$index}}].email',
								type: 'body',
							},
						},
						description: 'Email of the receipient',
					},
				],
			},
		],
		required: true,
	},
	{
		displayName: 'Additional Parameters',
		name: 'additionalParameters',
		placeholder: 'Add Parameter',
		description: 'Additional fields to add',
		type: 'collection',
		default: {},
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'send',
				],
			},
		},
		options: [
			{
				displayName: 'Receipients BCC',
				name: 'receipientsBCC',
				placeholder: 'Add BCC',
				type: 'fixedCollection',
				typeOptions: {
					multipleValues: true,
				},
				default: {},
				options: [
					{
						name: 'receipientBcc',
						displayName: 'Receipient',
						values: [
							{
								displayName: 'Name',
								name: 'name',
								type: 'string',
								default: '',
								routing: {
									send: {
										property: '=bcc[{{$index}}].name',
										type: 'body',
									},
								},
								description: 'Name of the BCC receipient',
							},
							{
								displayName: 'Email',
								name: 'email',
								type: 'string',
								default: '',
								routing: {
									send: {
										property: '=bcc[{{$index}}].email',
										type: 'body',
									},
								},
								description: 'Email of the BCC receipient',
							},
						],
					},
				],
			},
			{
				displayName: 'Receipients CC',
				name: 'receipientsCC',
				placeholder: 'Add CC',
				type: 'fixedCollection',
				typeOptions: {
					multipleValues: true,
				},
				default: {},
				options: [
					{
						name: 'receipientCc',
						displayName: 'Receipient',
						values: [
							{
								displayName: 'Name',
								name: 'name',
								type: 'string',
								default: '',
								routing: {
									send: {
										property: '=cc[{{$index}}].name',
										type: 'body',
									},
								},
								description: 'Name of the CC receipient',
							},
							{
								displayName: 'Email',
								name: 'email',
								type: 'string',
								default: '',
								routing: {
									send: {
										property: '=cc[{{$index}}].email',
										type: 'body',
									},
								},
								description: 'Email of the CC receipient',
							},
						],
					},
				],
			},
		],
	},
];

const sendHtmlTemplateEmailFields: INodeProperties[] = [
	{
		type: 'number',
		name: 'templateId',
		displayName: 'Template ID',
		default: 0,
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'sendTemplate',
				],
			},
		},
		routing: {
			send: {
				type: 'body',
				property: 'templateId',
			},
		},
	},
	{
		displayName: 'Receipients',
		name: 'receipients',
		placeholder: 'Add Receipient',
		type: 'fixedCollection',
		typeOptions: {
			multipleValues: true,
		},
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'sendTemplate',
				],
			},
		},
		default: {},
		options: [
			{
				name: 'receipient',
				displayName: 'Receipient',
				values: [
					{
						displayName: 'Name',
						name: 'name',
						type: 'string',
						default: '',
						routing: {
							send: {
								property: '=to[{{$index}}].name',
								type: 'body',
							},
						},
						description: 'Name of the receipient',
					},
					{
						displayName: 'Email',
						name: 'email',
						type: 'string',
						default: '',
						routing: {
							send: {
								property: '=to[{{$index}}].email',
								type: 'body',
							},
						},
						description: 'Email of the receipient',
					},
				],
			},
		],
		required: true,
	},
	{
		type: 'collection',
		name: 'templateParams',
		displayName: 'Additional Fields',
		default: {},
		displayOptions: {
			show: {
				resource: [
					'email',
				],
				operation: [
					'sendTemplate',
				],
			},
		},
		options: [
			{
				displayName: 'Template Parameters',
				name: 'templateParameters',
				placeholder: 'Add Parameter',
				type: 'fixedCollection',
				typeOptions: {
					multipleValues: true,
				},
				options: [
					{
						name: 'parameterValues',
						displayName: 'Parameter',
						values: [
							{
								displayName: 'Parameter Key',
								name: 'parameterKey',
								type: 'string',
								default: '',
							},
							{
								displayName: 'Parameter Value',
								name: 'parameterValue',
								type: 'string',
								default: '',
								routing: {
									send: {
										value: '={{$value}}',
										property: '=params.{{$parent.parameterKey}}',
										type: 'body',
									},
								},
							},
						],
					},
				],
				default: {},
				description: 'Pass the set of attributes to customize the template',
			},
		],
	},
];

export const emailFields: INodeProperties[] = [
	...sendHtmlEmailFields,
	...sendHtmlTemplateEmailFields,
];
