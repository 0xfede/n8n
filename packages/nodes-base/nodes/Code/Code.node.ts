import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { getSandboxContext, Sandbox } from './Sandbox';
import { getSandboxContextPython, SandboxPython } from './SandboxPython';
import { standardizeOutput } from './utils';
import type { CodeNodeMode } from './utils';

export class Code implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Code',
		name: 'code',
		icon: 'fa:code',
		group: ['transform'],
		version: 1,
		description: 'Run custom JavaScript code',
		defaults: {
			name: 'Code',
			color: '#FF9922',
		},
		inputs: ['main'],
		outputs: ['main'],
		parameterPane: 'wide',
		properties: [
			{
				displayName: 'Mode',
				name: 'mode',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Run Once for All Items',
						value: 'runOnceForAllItems',
						description: 'Run this code only once, no matter how many input items there are',
					},
					{
						name: 'Run Once for Each Item',
						value: 'runOnceForEachItem',
						description: 'Run this code as many times as there are input items',
					},
				],
				default: 'runOnceForAllItems',
			},
			{
				displayName: 'Language',
				name: 'language',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'JavaScript',
						value: 'javaScript',
					},
					{
						name: 'Python',
						value: 'python',
					},
				],
				default: 'javaScript',
			},

			// JavaScript
			{
				displayName: 'JavaScript',
				name: 'jsCode',
				typeOptions: {
					editor: 'codeNodeEditor',
				},
				displayOptions: {
					show: {
						language: ['javaScript'],
					},
				},
				type: 'string',
				default: '', // set by component
				description:
					'JavaScript code to execute.<br><br>Tip: You can use luxon vars like <code>$today</code> for dates and <code>$jmespath</code> for querying JSON structures. <a href="https://docs.n8n.io/nodes/n8n-nodes-base.function">Learn more</a>.',
				noDataExpression: true,
			},
			{
				displayName:
					'Type <code>$</code> for a list of <a target="_blank" href="https://docs.n8n.io/code-examples/methods-variables-reference/">special vars/methods</a>. Debug by using <code>console.log()</code> statements and viewing their output in the browser console.',
				name: 'notice',
				type: 'notice',
				displayOptions: {
					show: {
						language: ['javaScript'],
					},
				},
				default: '',
			},

			// Python
			{
				displayName: 'Python',
				// TODO: Rename
				name: 'jsCode',
				// name: 'pythonCode',
				typeOptions: {
					editor: 'codeNodeEditor',
				},
				displayOptions: {
					show: {
						language: ['python'],
					},
				},
				type: 'string',
				default: '', // set by component
				description:
					'Python code to execute.<br><br>Tip: You can use luxon vars like <code>_today</code> for dates and <code>$_mespath</code> for querying JSON structures. <a href="https://docs.n8n.io/nodes/n8n-nodes-base.function">Learn more</a>.',
				noDataExpression: true,
			},
			{
				displayName:
					'Type <code>_</code> for a list of <a target="_blank" href="https://docs.n8n.io/code-examples/methods-variables-reference/">special vars/methods</a>. Debug by using <code>print()</code> statements and viewing their output in the browser console.',
				name: 'notice',
				type: 'notice',
				displayOptions: {
					show: {
						language: ['python'],
					},
				},
				default: '',
			},
		],
	};

	async execute(this: IExecuteFunctions) {
		let items = this.getInputData();

		const nodeMode = this.getNodeParameter('mode', 0) as CodeNodeMode;
		const workflowMode = this.getMode();

		const language = this.getNodeParameter('language', 0) as string;

		if (language === 'python') {
			const pythonCode = this.getNodeParameter('jsCode', 0) as string;

			// ----------------------------------
			//        runOnceForAllItems
			// ----------------------------------

			if (nodeMode === 'runOnceForAllItems') {
				const context = getSandboxContextPython.call(this);

				if (workflowMode === 'manual') {
					context.print = this.sendMessageToUI;
				}

				const sandbox = new SandboxPython(workflowMode, nodeMode);

				try {
					items = (await sandbox.runCode(context, pythonCode)) as INodeExecutionData[];
				} catch (error) {
					sandbox.close();
					if (!this.continueOnFail()) return Promise.reject(error);
					items = [{ json: { error: error.message } }];
				}
				sandbox.close();

				for (const item of items) {
					standardizeOutput(item.json);
				}

				return this.prepareOutputData(items);
			}

			// ----------------------------------
			//        runOnceForEachItem
			// ----------------------------------

			const returnData: INodeExecutionData[] = [];

			let item: INodeExecutionData | undefined;

			const sandbox = new SandboxPython(workflowMode, nodeMode);

			for (let index = 0; index < items.length; index++) {
				const context = getSandboxContextPython.call(this, index);

				if (workflowMode === 'manual') {
					context.print = this.sendMessageToUI;
				}

				try {
					item = (await sandbox.runCode(context, pythonCode, index)) as INodeExecutionData;
				} catch (error) {
					if (!this.continueOnFail()) {
						sandbox.close();
						return Promise.reject(error);
					}
					returnData.push({ json: { error: error.message } });
					items = [{ json: { error: error.message } }];
				}

				if (item) {
					returnData.push({
						json: standardizeOutput(item.json),
						pairedItem: { item: index },
						...(item.binary && { binary: item.binary }),
					});
				}
			}

			sandbox.close();

			return this.prepareOutputData(returnData);
		}

		// ----------------------------------
		//        runOnceForAllItems
		// ----------------------------------

		if (nodeMode === 'runOnceForAllItems') {
			const jsCodeAllItems = this.getNodeParameter('jsCode', 0) as string;

			const context = getSandboxContext.call(this);
			const sandbox = new Sandbox(context, workflowMode, nodeMode);

			if (workflowMode === 'manual') {
				sandbox.on('console.log', this.sendMessageToUI);
			}

			try {
				items = await sandbox.runCode(jsCodeAllItems);
			} catch (error) {
				if (!this.continueOnFail()) return Promise.reject(error);
				items = [{ json: { error: error.message } }];
			}

			for (const item of items) {
				standardizeOutput(item.json);
			}

			return this.prepareOutputData(items);
		}

		// ----------------------------------
		//        runOnceForEachItem
		// ----------------------------------

		const returnData: INodeExecutionData[] = [];

		for (let index = 0; index < items.length; index++) {
			let item = items[index];

			const jsCodeEachItem = this.getNodeParameter('jsCode', index) as string;

			const context = getSandboxContext.call(this, index);
			const sandbox = new Sandbox(context, workflowMode, nodeMode);

			if (workflowMode === 'manual') {
				sandbox.on('console.log', this.sendMessageToUI);
			}

			try {
				item = await sandbox.runCode(jsCodeEachItem, index);
			} catch (error) {
				if (!this.continueOnFail()) return Promise.reject(error);
				returnData.push({ json: { error: error.message } });
			}

			if (item) {
				returnData.push({
					json: standardizeOutput(item.json),
					pairedItem: { item: index },
					...(item.binary && { binary: item.binary }),
				});
			}
		}

		return this.prepareOutputData(returnData);
	}
}
