export function createPage({
	instanceId,
	webhookUrl,
	showWelcomeScreen,
	i18n: { en },
	initialMessages,
	authentication,
}: {
	instanceId: string;
	webhookUrl?: string;
	showWelcomeScreen?: boolean;
	i18n: {
		en: Record<string, string>;
	};
	initialMessages: string[];
	mode: 'test' | 'production';
	authentication: 'none' | 'basicAuth' | 'n8nAuth';
}) {
	return `<doctype html>
	<html lang="en">
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>Chat</title>
			<link href="https://cdn.jsdelivr.net/npm/normalize.css@8.0.1/normalize.min.css" rel="stylesheet" />
			<link href="https://cdn.jsdelivr.net/npm/@n8n/chat/style.css" rel="stylesheet" />
		</head>
		<body>
			<script type="module">
				import { createChat } from 'https://cdn.jsdelivr.net/npm/@n8n/chat/chat.bundle.es.js';

				(async function () {
					const authentication = '${authentication}';
					let metadata;
					if (authentication === 'n8nAuth') {
						try {
							const response = await fetch('/rest/login', {
									method: 'GET'
							});

							if (response.status !== 200) {
								throw new Error('Not logged in');
							}

							const responseData = await response.json();
							metadata = {
								user: {
									id: responseData.data.id,
									firstName: responseData.data.firstName,
									lastName: responseData.data.lastName,
									email: responseData.data.email,
								},
							};
						} catch (error) {
							window.location.href = '/signin';
							return;
						}
					}

					createChat({
						mode: 'fullscreen',
						webhookUrl: '${webhookUrl}',
						showWelcomeScreen: ${showWelcomeScreen},
						metadata: metadata,
						webhookConfig: {
							headers: {
								'Content-Type': 'application/json',
								'X-Instance-Id': '${instanceId}',
							}
						},
						i18n: {
							${en ? `en: ${JSON.stringify(en)},` : ''}
						},
						${initialMessages.length ? `initialMessages: ${JSON.stringify(initialMessages)},` : ''}
					});
				})();
			</script>
		</body>
	</html>`;
}
