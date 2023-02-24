import { defineComponent } from 'vue';

import { WorkflowTitleStatus } from '@/Interface';

export const titleChange = defineComponent({
	methods: {
		/**
		 * Change title of n8n tab
		 *
		 * @param {string} workflow Name of workflow
		 * @param {WorkflowTitleStatus} status Status of workflow
		 */
		$titleSet(workflow: string, status: WorkflowTitleStatus) {
			let icon = '⚠️';
			if (status === 'EXECUTING') {
				icon = '🔄';
			} else if (status === 'IDLE') {
				icon = '▶️';
			}

			window.document.title = `n8n - ${icon} ${workflow}`;
		},

		$titleReset() {
			document.title = 'n8n - Workflow Automation';
		},
	},
});
