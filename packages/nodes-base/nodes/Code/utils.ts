import { NodeOperationError } from 'n8n-workflow';
import { END_SCRIPT_ERRORS } from './errors';
import type { IDataObject, INode } from 'n8n-workflow';

export const deepCopy = <T>(toCopy: T): T => JSON.parse(JSON.stringify(toCopy));

/**
 * Stringify any non-standard JS objects (e.g. `Date`, `RegExp`) inside output items at any depth.
 */
export function standardizeOutput(output: IDataObject) {
	for (const [key, value] of Object.entries(output)) {
		if (!isTraversable(value)) continue;

		output[key] =
			value.constructor.name !== 'Object'
				? JSON.stringify(value) // Date, RegExp, etc.
				: standardizeOutput(value);
	}

	return output;
}

export function isObject(maybe: unknown): maybe is { [key: string]: unknown } {
	return typeof maybe === 'object' && maybe !== null && !Array.isArray(maybe);
}

function isTraversable(maybe: unknown): maybe is IDataObject {
	return isObject(maybe) && Object.keys(maybe).length > 0;
}

export type CodeNodeMode = 'runOnceForAllItems' | 'runOnceForEachItem';
