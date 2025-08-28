import { z } from 'zod';

import { PROJECT_OWNER_ROLE_SLUG } from './constants.ee';

export const roleNamespaceSchema = z.enum(['global', 'project', 'credential', 'workflow']);

export const globalRoleSchema = z.enum(['global:owner', 'global:admin', 'global:member']);

export const assignableGlobalRoleSchema = globalRoleSchema.exclude([
	'global:owner', // Owner cannot be changed
]);

export const personalRoleSchema = z.enum([
	'project:personalOwner', // personalOwner is only used for personal projects
]);

// Those are the system roles for projects assignable to a user
export const teamRoleSchema = z.enum(['project:admin', 'project:editor', 'project:viewer']);

// Custom project role can be anything but the system roles
export const customProjectRoleSchema = z
	.string()
	.nonempty()
	.refine(
		(val) => val !== PROJECT_OWNER_ROLE_SLUG && !Object.keys(teamRoleSchema.Values).includes(val),
		{
			message: 'This role value is not assignable',
		},
	);

// Those are all the system roles for projects
export const systemProjectRoleSchema = z.union([personalRoleSchema, teamRoleSchema]);

// Those are the roles that can be assigned to a user for a project (all roles except personalOwner)
export const assignableProjectRoleSchema = z.union([teamRoleSchema, customProjectRoleSchema]);

export const projectRoleSchema = z.union([systemProjectRoleSchema, customProjectRoleSchema]);

export const credentialSharingRoleSchema = z.enum(['credential:owner', 'credential:user']);

export const workflowSharingRoleSchema = z.enum(['workflow:owner', 'workflow:editor']);
