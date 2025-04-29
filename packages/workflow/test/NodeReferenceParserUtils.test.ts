import type { INode } from '../src/Interfaces';
import {
	hasDotNotationBannedChar,
	backslashEscape,
	dollarEscape,
	applyAccessPatterns,
	extractReferencesInNodeExpressions,
} from '../src/NodeReferenceParserUtils';

const makeNode = (name: string, expressions?: string[]) =>
	({
		parameters: Object.fromEntries(expressions?.map((x, i) => [`p${i}`, `={{ ${x} }}`]) ?? []),
		name,
	}) as INode;

describe('NodeReferenceParserUtils', () => {
	describe('hasDotNotationBannedChar', () => {
		it('should return true for strings with banned characters', () => {
			expect(hasDotNotationBannedChar('1abc')).toBe(true);
			expect(hasDotNotationBannedChar('abc!')).toBe(true);
			expect(hasDotNotationBannedChar('abc@')).toBe(true);
		});

		it('should return false for strings without banned characters', () => {
			expect(hasDotNotationBannedChar('abc')).toBe(false);
			expect(hasDotNotationBannedChar('validName')).toBe(false);
		});
	});

	describe('backslashEscape', () => {
		it('should escape special characters with a backslash', () => {
			expect(backslashEscape('abc.def')).toBe('abc\\.def');
			expect(backslashEscape('[abc]')).toBe('\\[abc\\]');
			expect(backslashEscape('a+b')).toBe('a\\+b');
		});

		it('should return the same string if no escapable characters are present', () => {
			expect(backslashEscape('abc')).toBe('abc');
		});
	});

	describe('dollarEscape', () => {
		it('should escape dollar signs with double dollar signs', () => {
			expect(dollarEscape('$abc')).toBe('$$abc');
			expect(dollarEscape('abc$')).toBe('abc$$');
			expect(dollarEscape('$a$b$c')).toBe('$$a$$b$$c');
		});

		it('should return the same string if no dollar signs are present', () => {
			expect(dollarEscape('abc')).toBe('abc');
		});
	});

	describe('applyAccessPatterns', () => {
		it.each([
			{
				expression: '$node["oldName"].data',
				previousName: 'oldName',
				newName: 'newName',
				expected: '$node["newName"].data',
			},
			{
				expression: '$node.oldName.data',
				previousName: 'oldName',
				newName: 'new.Name',
				expected: '$node["new.Name"].data',
			},
			{
				expression: '$node["someOtherName"].data',
				previousName: 'oldName',
				newName: 'newName',
				expected: '$node["someOtherName"].data',
			},
			{
				expression: '$node["oldName"].data + $node["oldName"].info',
				previousName: 'oldName',
				newName: 'newName',
				expected: '$node["newName"].data + $node["newName"].info',
			},
			{
				expression: '$items("oldName", 0)',
				previousName: 'oldName',
				newName: 'newName',
				expected: '$items("newName", 0)',
			},
			{
				expression: "$items('oldName', 0)",
				previousName: 'oldName',
				newName: 'newName',
				expected: "$items('newName', 0)",
			},
			{
				expression: "$('oldName')",
				previousName: 'oldName',
				newName: 'newName',
				expected: "$('newName')",
			},
			{
				expression: '$("oldName")',
				previousName: 'oldName',
				newName: 'newName',
				expected: '$("newName")',
			},
			{
				expression: '$node["oldName"].data + $items("oldName", 0) + $("oldName")',
				previousName: 'oldName',
				newName: 'newName',
				expected: '$node["newName"].data + $items("newName", 0) + $("newName")',
			},
			{
				expression: '$node["oldName"].data + $items("oldName", 0)',
				previousName: 'oldName',
				newName: 'new-Name',
				expected: '$node["new-Name"].data + $items("new-Name", 0)',
			},
			{
				expression: '$node["old-Name"].data + $items("old-Name", 0)',
				previousName: 'old-Name',
				newName: 'newName',
				expected: '$node["newName"].data + $items("newName", 0)',
			},
			{
				expression: 'someRandomExpression("oldName")',
				previousName: 'oldName',
				newName: 'newName',
				expected: 'someRandomExpression("oldName")',
			},
			{
				expression: '$("old\\"Name")',
				previousName: 'old\\"Name',
				newName: 'n\\\'ew\\"Name',
				expected: '$("n\\\'ew\\"Name")',
			},
		])(
			'should correctly transform expression "$expression" with previousName "$previousName" and newName "$newName"',
			({ expression, previousName, newName, expected }) => {
				const result = applyAccessPatterns(expression, previousName, newName);
				expect(result).toBe(expected);
			},
		);
	});

	describe('extractReferencesInNodeExpressions', () => {
		let nodes: INode[] = [];
		let nodeNames: string[] = [];
		let startNodeName = 'Start';
		beforeEach(() => {
			nodes = [
				makeNode('B', ['$("A").item.json.myField']),
				makeNode('C', ['$("A").first().json.myField.anotherField']),
			];
			nodeNames = ['A', 'B', 'C'];
			startNodeName = 'Start';
		});
		it('should extract used expressions', () => {
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([
				['myField', '$("A").item.json.myField'],
				['myField_anotherField_first', '$("A").first().json.myField.anotherField'],
			]);
			expect(result.nodes).toEqual([
				{
					name: 'B',
					parameters: { p0: "={{ $('Start').item.json.myField }}" },
				},
				{
					name: 'C',
					parameters: { p0: "={{ $('Start').first().json.myField_anotherField_first }}" },
				},
			]);
		});

		it('should handle simple name clashes', () => {
			nodes = [
				makeNode('B', ['$("A").item.json.myField']),
				makeNode('C', ['$("D").item.json.myField']),
				makeNode('E', ['$("F").item.json.myField']),
			];
			nodeNames = ['A', 'B', 'C', 'D', 'E', 'F'];
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([
				['myField', '$("A").item.json.myField'],
				['D_myField', '$("D").item.json.myField'],
				['F_myField', '$("F").item.json.myField'],
			]);
			expect(result.nodes).toEqual([
				{
					name: 'B',
					parameters: { p0: "={{ $('Start').item.json.myField }}" },
				},
				{
					name: 'C',
					parameters: { p0: "={{ $('Start').item.json.D_myField }}" },
				},
				{
					name: 'E',
					parameters: { p0: "={{ $('Start').item.json.F_myField }}" },
				},
			]);
		});

		it('should handle complex name clashes', () => {
			nodes = [
				makeNode('F', ['$("A").item.json.myField']),
				makeNode('B', ['$("A").item.json.Node_Name_With_Gap_myField']),
				makeNode('C', ['$("D").item.json.Node_Name_With_Gap_myField']),
				makeNode('E', ['$("Node_Name_With_Gap").item.json.myField']),
			];
			nodeNames = ['A', 'B', 'C', 'D', 'E', 'F', 'Node_Name_With_Gap'];
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([
				['myField', '$("A").item.json.myField'],
				['Node_Name_With_Gap_myField', '$("A").item.json.Node_Name_With_Gap_myField'],
				['D_Node_Name_With_Gap_myField', '$("D").item.json.Node_Name_With_Gap_myField'],
				// This is the `myField` variable from node 'E', referencing $("Node_Name_With_Gap").item.json.myField
				// It first has a clash with A.myField, requiring its node name to come attached
				// And then has _1 because it clashes B.Node_Name_With_Gap_myField
				['Node_Name_With_Gap_myField_1', '$("Node_Name_With_Gap").item.json.myField'],
			]);
			expect(result.nodes).toEqual([
				{ name: 'F', parameters: { p0: "={{ $('Start').item.json.myField }}" } },
				{
					name: 'B',
					parameters: { p0: "={{ $('Start').item.json.Node_Name_With_Gap_myField }}" },
				},
				{
					name: 'C',
					parameters: { p0: "={{ $('Start').item.json.D_Node_Name_With_Gap_myField }}" },
				},
				{
					name: 'E',
					parameters: { p0: "={{ $('Start').item.json.Node_Name_With_Gap_myField_1 }}" },
				},
			]);
		});

		it('should handle code node', () => {
			nodes = [
				{
					parameters: {
						jsCode:
							"for (const item of $input.all()) {\n  item.json.myNewField = $('DebugHelper').first().json.uid;\n}\n\nreturn $input.all();",
					},
					type: 'n8n-nodes-base.code',
					typeVersion: 2,
					position: [660, 0],
					id: 'c9de02d0-982a-4f8c-9af7-93f63795aa9b',
					name: 'Code',
				},
			];
			nodeNames = ['DebugHelper', 'Code'];
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([
				['uid_first', "$('DebugHelper').first().json.uid"],
			]);
			expect(result.nodes).toEqual([
				{
					parameters: {
						jsCode:
							"for (const item of $input.all()) {\n  item.json.myNewField = $('Start').first().json.uid_first;\n}\n\nreturn $input.all();",
					},
					type: 'n8n-nodes-base.code',
					typeVersion: 2,
					position: [660, 0],
					id: 'c9de02d0-982a-4f8c-9af7-93f63795aa9b',
					name: 'Code',
				},
			]);
		});
		it('should not extract expression referencing node in subGraph', () => {
			nodes = [
				makeNode('B', ['$("A").item.json.myField']),
				makeNode('C', ['$("B").first().json.myField.anotherField']),
			];
			nodeNames = ['A', 'B', 'C'];
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([['myField', '$("A").item.json.myField']]);
			expect(result.nodes).toEqual([
				{
					name: 'B',
					parameters: { p0: "={{ $('Start').item.json.myField }}" },
				},
				{
					name: 'C',
					parameters: { p0: '={{ $("B").first().json.myField.anotherField }}' },
				},
			]);
		});
		it('should throw if node name clashes with start name', () => {
			nodes = [makeNode('Start', ['$("A").item.json.myField'])];
			nodeNames = ['A', 'Start'];
			expect(() => extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName)).toThrow();
		});

		it('should support custom Start node name', () => {
			nodes = [makeNode('Start', ['$("A").item.json.myField'])];
			nodeNames = ['A', 'Start'];
			startNodeName = 'A different start name';
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([['myField', '$("A").item.json.myField']]);
			expect(result.nodes).toEqual([
				{
					name: 'Start',
					parameters: { p0: "={{ $('A different start name').item.json.myField }}" },
				},
			]);
		});
		it('should throw if called with node in subgraph whose name is not in nodeNames list', () => {
			nodes = [makeNode('B', ['$("A").item.json.myField'])];
			nodeNames = ['A'];
			expect(() => extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName)).toThrow();
		});
		// it('handles multiple expressions referencing different nodes in the same string')
		// it('handles multiple expressions referencing different nested bits of the same field')
		// it('handles first(), last(), all() and items at the same time')
		it('handles supported itemMatching examples', () => {
			nodes = [
				makeNode('B', [
					'$("A").itemMatching(0).json.myField',
					'$("A").itemMatching(1).json.myField',
					'$("C").itemMatching(1).json.myField',
					'$("A").itemMatching(20).json.myField',
				]),
			];
			nodeNames = ['A', 'B', 'C'];
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([
				['myField_itemMatching_0', '$("A").itemMatching(0).json.myField'],
				['myField_itemMatching_1', '$("A").itemMatching(1).json.myField'],
				['C_myField_itemMatching_1', '$("C").itemMatching(1).json.myField'],
				['myField_itemMatching_20', '$("A").itemMatching(20).json.myField'],
			]);
			expect(result.nodes).toEqual([
				{
					name: 'B',
					parameters: {
						p0: "={{ $('Start').itemMatching(0).json.myField_itemMatching_0 }}",
						p1: "={{ $('Start').itemMatching(1).json.myField_itemMatching_1 }}",
						p2: "={{ $('Start').itemMatching(1).json.C_myField_itemMatching_1 }}",
						p3: "={{ $('Start').itemMatching(20).json.myField_itemMatching_20 }}",
					},
				},
			]);
		});
		it('does not throw for complex itemMatching example', () => {
			nodes = [
				makeNode('B', [
					'$("A").itemMatching(Math.PI).json.myField',
					'$("A").itemMatching(eval("const fib = (n) => n < 2 ? 1 : (fib(n - 1) + fib(n-2)); fib(15)")).json.anotherField',
					'$("A").itemMatching($("A").itemMatch(1).json.myField).json.myField',
				]),
			];
			nodeNames = ['A', 'B'];
			expect(() =>
				extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName),
			).not.toThrow();
		});
		it('should handle multiple expressions', () => {
			nodes = [
				makeNode('B', ['$("A").item.json.myField', '$("C").item.json.anotherField']),
				makeNode('D', ['$("A").item.json.myField', '$("B").item.json.someField']),
			];
			nodeNames = ['A', 'B', 'C', 'D'];
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([
				['myField', '$("A").item.json.myField'],
				['anotherField', '$("C").item.json.anotherField'],
			]);
			expect(result.nodes).toEqual([
				{
					name: 'B',
					parameters: {
						p0: "={{ $('Start').item.json.myField }}",
						p1: "={{ $('Start').item.json.anotherField }}",
					},
				},
				{
					name: 'D',
					parameters: {
						p0: "={{ $('Start').item.json.myField }}",
						p1: '={{ $("B").item.json.someField }}',
					},
				},
			]);
		});
		it('should support handle calls to normal js functions on the data accessor', () => {
			nodes = [makeNode('A', ['$("B B").first().toJsonObject().randomJSFunction()'])];
			nodeNames = ['A', 'B B'];
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([['B_B_first', '$("B B").first()']]);
			expect(result.nodes).toEqual([
				{
					name: 'A',
					parameters: {
						p0: "={{ $('Start').first().json.B_B_first.toJsonObject().randomJSFunction() }}",
					},
				},
			]);
		});
		it('should support handle spaces and special characters in nodeNames', () => {
			nodes = [
				makeNode('a_=-9-0!@#!%^$%&*(', ['$("A").item.json.myField']),
				makeNode('A node with spaces', [
					'$("A \\" |[w.e,i,r$d]| `\' Ñode  \\$\\( Name \\)").item.json.myField',
				]),
			];
			nodeNames = [
				'A',
				'A node with spaces',
				'A \\" |[w.e,i,r$d]| `\' Ñode  \\$\\( Name \\)',
				'a_=-9-0!@#!%^$%&*(',
			];
			const result = extractReferencesInNodeExpressions(nodes, nodeNames, startNodeName);
			expect([...result.variables.entries()]).toEqual([
				['myField', '$("A").item.json.myField'],
				[
					'A__weir$d__ode__$_Name__myField',
					'$("A \\" |[w.e,i,r$d]| `\' Ñode  \\$\\( Name \\)").item.json.myField',
				],
			]);
			expect(result.nodes).toEqual([
				{
					name: 'a_=-9-0!@#!%^$%&*(',
					parameters: { p0: "={{ $('Start').item.json.myField }}" },
				},
				{
					name: 'A node with spaces',
					parameters: { p0: "={{ $('Start').item.json.A__weir$d__ode__$_Name__myField }}" },
				},
			]);
		});
	});
});
