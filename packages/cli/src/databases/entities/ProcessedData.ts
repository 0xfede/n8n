import { CreateDateColumn, Entity, Index, PrimaryColumn } from 'typeorm';

import * as config from '../../../config';
// eslint-disable-next-line import/no-cycle
import { DatabaseType, IProcessedDataDb } from '../..';

function getTimestampSyntax() {
	const dbType = config.getEnv('database.type');

	const map: { [key in DatabaseType]: string } = {
		sqlite: "STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')",
		postgresdb: 'CURRENT_TIMESTAMP(3)',
		mysqldb: 'CURRENT_TIMESTAMP(3)',
		mariadb: 'CURRENT_TIMESTAMP(3)',
	};

	return map[dbType];
}

@Entity()
@Index(['workflowId', 'context', 'value'], { unique: true })
export class ProcessedData implements IProcessedDataDb {
	// @Column('varchar')
	@PrimaryColumn('varchar')
	value: string;

	// @Column('varchar')
	@PrimaryColumn('varchar')
	context: string;

	// @Column()
	@PrimaryColumn()
	workflowId: string;

	@CreateDateColumn({ precision: 3, default: () => getTimestampSyntax() })
	createdAt: Date;
}
