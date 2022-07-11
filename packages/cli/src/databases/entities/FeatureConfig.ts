/* eslint-disable import/no-cycle */
import { Column, ColumnOptions, Entity, PrimaryColumn } from 'typeorm';
import * as config from '../../../config';
import { DatabaseType, IFeatureConfigDb } from '../..';
import type { ActiveDirectoryConfig } from '../../ActiveDirectory/types';

function resolveDataType(dataType: string) {
	const dbType = config.getEnv('database.type');

	const typeMap: { [key in DatabaseType]: { [key: string]: string } } = {
		sqlite: {
			json: 'simple-json',
		},
		postgresdb: {
			datetime: 'timestamptz',
		},
		mysqldb: {},
		mariadb: {},
	};

	return typeMap[dbType][dataType] ?? dataType;
}

@Entity()
export class FeatureConfig implements IFeatureConfigDb {
	@PrimaryColumn()
	name: string;

	@Column({
		type: resolveDataType('json') as ColumnOptions['type'],
		default: '{}',
	})
	data: string | ActiveDirectoryConfig;
}
