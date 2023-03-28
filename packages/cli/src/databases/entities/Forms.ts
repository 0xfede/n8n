import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Forms {
	@PrimaryGeneratedColumn()
	id: number;

	@Column('text')
	title: string;

	@Column('json')
	schema: string;
}
