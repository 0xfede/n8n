import {
	type CredentialsEntity,
	type SharedCredentials,
	type SharedWorkflow,
	type User,
	type ListQueryDb,
	type ScopesField,
	type ProjectRelation,
	GLOBAL_ADMIN_ROLE,
} from '@n8n/db';
import { Service } from '@n8n/di';
import type { AssignableProjectRole, Scope } from '@n8n/permissions';
import {
	ALL_ROLES,
	combineScopes,
	getAuthPrincipalScopes,
	getRoleScopes,
	PROJECT_ADMIN_ROLE_SLUG,
	PROJECT_EDITOR_ROLE_SLUG,
	PROJECT_VIEWER_ROLE_SLUG,
} from '@n8n/permissions';
import { UnexpectedError } from 'n8n-workflow';

import { License } from '@/license';

@Service()
export class RoleService {
	constructor(private readonly license: License) {}

	getAllRoles() {
		Object.values(ALL_ROLES).forEach((entries) => {
			entries.forEach((entry) => {
				entry.licensed = this.isRoleLicensed(entry.role);
			});
		});
		return ALL_ROLES;
	}

	addScopes(
		rawWorkflow: ListQueryDb.Workflow.WithSharing | ListQueryDb.Workflow.WithOwnedByAndSharedWith,
		user: User,
		userProjectRelations: ProjectRelation[],
	): ListQueryDb.Workflow.WithScopes;
	addScopes(
		rawCredential: CredentialsEntity,
		user: User,
		userProjectRelations: ProjectRelation[],
	): CredentialsEntity & ScopesField;
	addScopes(
		rawCredential:
			| ListQueryDb.Credentials.WithSharing
			| ListQueryDb.Credentials.WithOwnedByAndSharedWith,
		user: User,
		userProjectRelations: ProjectRelation[],
	): ListQueryDb.Credentials.WithScopes;
	addScopes(
		rawEntity:
			| CredentialsEntity
			| ListQueryDb.Workflow.WithSharing
			| ListQueryDb.Credentials.WithOwnedByAndSharedWith
			| ListQueryDb.Credentials.WithSharing
			| ListQueryDb.Workflow.WithOwnedByAndSharedWith,
		user: User,
		userProjectRelations: ProjectRelation[],
	):
		| (CredentialsEntity & ScopesField)
		| ListQueryDb.Workflow.WithScopes
		| ListQueryDb.Credentials.WithScopes {
		const shared = rawEntity.shared;
		const entity = rawEntity as
			| (CredentialsEntity & ScopesField)
			| ListQueryDb.Workflow.WithScopes
			| ListQueryDb.Credentials.WithScopes;

		entity.scopes = [];

		if (shared === undefined) {
			return entity;
		}

		if (!('active' in entity) && !('type' in entity)) {
			throw new UnexpectedError('Cannot detect if entity is a workflow or credential.');
		}

		entity.scopes = this.combineResourceScopes(
			'active' in entity ? 'workflow' : 'credential',
			user,
			shared,
			userProjectRelations,
		);

		return entity;
	}

	combineResourceScopes(
		type: 'workflow' | 'credential',
		user: User,
		shared: SharedCredentials[] | SharedWorkflow[],
		userProjectRelations: ProjectRelation[],
	): Scope[] {
		const globalScopes = getAuthPrincipalScopes(user, [type]);
		const scopesSet: Set<Scope> = new Set(globalScopes);
		for (const sharedEntity of shared) {
			const pr = userProjectRelations.find(
				(p) => p.projectId === (sharedEntity.projectId ?? sharedEntity.project.id),
			);
			let projectScopes: Scope[] = [];
			if (pr) {
				projectScopes = pr.role.scopes.map((s) => s.slug);
			}
			const resourceMask = getRoleScopes(sharedEntity.role);
			const mergedScopes = combineScopes(
				{
					global: globalScopes,
					project: projectScopes,
				},
				{ sharing: resourceMask },
			);
			mergedScopes.forEach((s) => scopesSet.add(s));
		}
		return [...scopesSet].sort();
	}

	isRoleLicensed(role: AssignableProjectRole) {
		// TODO: move this info into FrontendSettings
		switch (role) {
			case PROJECT_ADMIN_ROLE_SLUG:
				return this.license.isProjectRoleAdminLicensed();
			case PROJECT_EDITOR_ROLE_SLUG:
				return this.license.isProjectRoleEditorLicensed();
			case PROJECT_VIEWER_ROLE_SLUG:
				return this.license.isProjectRoleViewerLicensed();
			case GLOBAL_ADMIN_ROLE.slug:
				return this.license.isAdvancedPermissionsLicensed();
			default:
				// TODO: handle custom roles licensing
				return true;
		}
	}
}
