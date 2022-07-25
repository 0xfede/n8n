/* eslint-disable import/no-cycle */
import express from 'express';
import { LdapManager } from '../LdapManager';
import { getLdapConfig, getLdapSyncronizations, updateActiveDirectoryConfig } from '../helpers';
import type { LdapConfig } from '../types';

export const ldapController = express.Router();

/**
 * GET /active-directory/config
 */
ldapController.get('/config', async (req: express.Request, res: express.Response) => {
	const { data } = await getLdapConfig();
	return res.status(200).json({ data });
});
/**
 * POST /active-directory/test-connection
 */
ldapController.post('/test-connection', async (req: express.Request, res: express.Response) => {
	try {
		await LdapManager.getInstance().service.testConnection();
	} catch (error) {
		const errorObject = error as { message: string };
		return res.status(400).json({ message: errorObject.message });
	}
	return res.status(200).json();
});

/**
 * PUT /active-directory/config
 */
ldapController.put('/config', async (req: LdapConfig.Update, res: express.Response) => {
	await updateActiveDirectoryConfig(req.body);

	const { data } = await getLdapConfig();

	LdapManager.updateConfig(data);

	return res.status(200).json(data);
});

/**
 * POST /active-directory/sync
 */
ldapController.post('/sync', async (req: LdapConfig.Sync, res: express.Response) => {
	const runType = req.body.type;

	await LdapManager.getInstance().sync.run(runType);

	return res.status(200).json({});
});

/**
 * GET /active-directory/sync
 */
ldapController.get('/sync', async (req: express.Request, res: express.Response) => {
	const data = await getLdapSyncronizations();
	return res.status(200).json({ data });
});
