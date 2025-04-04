import { useToast } from '@/composables/useToast';
import { STORES } from '@/constants';
import n8n from '@/extensions-sdk';
import { defineStore } from 'pinia';
import { ref } from 'vue';

export type Extension = {
	id: string;
	name: string;
	displayName: string;
	description: string;
	author: string;
	version: string;
	category: string;
	enabled: boolean;
	tags?: string[];
	minSDVersion?: string;
	setup: {
		frontend?: string;
		backend?: string;
	};
	contributes: unknown;
	path: string;
	initialized?: boolean;
};

const EXTENSION_SANDBOX_ID = 'extensions-host';

export type ExtensionSetupMethod = 'directImport' | 'shadowRealm' | 'iframe';

export const useExtensionsStore = defineStore(STORES.EXTENSIONS, () => {
	const extensions = ref<Extension[]>([]);

	const setupMethod = ref<ExtensionSetupMethod>('directImport');

	const toast = useToast();

	const loadExtensions = () => {
		// Load all manifests from the extensions directory
		const manifestModules = import.meta.glob('../../public/extensions/*/n8n.manifest.json', {
			eager: true,
		});

		const loaded: Extension[] = [];
		for (const path in manifestModules) {
			const extension = manifestModules[path].default;
			loaded.push({
				...extension,
				path,
				enabled: true,
			});
		}
		extensions.value = loaded;
	};

	const getAllSettingsExtensions = () => {
		return extensions.value.filter((extension) => {
			const contributes = extension.contributes as { settingsPage?: unknown };
			return contributes.settingsPage !== undefined;
		});
	};

	const getExtensionById = (id: string) => {
		const extension = extensions.value.find((e) => e.id === id);
		return extension;
	};

	const getSettingsExtension = (id: string) => {
		const settingsExtensions = getAllSettingsExtensions();
		const settingsExtension = settingsExtensions.find((extension) => extension.id === id);
		if (!settingsExtension) {
			throw new Error(`Settings extension with id "${id}" not found`);
		}
		return settingsExtension;
	};

	/**
	 * Option A: Load the extension using a direct import
	 * This is the simplest way to load an extension, but it is not sandboxed.
	 * This means that the extension has access to the global scope and can modify it.
	 * @param id
	 * @returns
	 */
	const setupExtensionUsingDirectImport = async (id: string) => {
		const extension = getExtensionById(id);
		if (!extension || !extension.enabled) {
			return;
		}
		if (!extension.setup.frontend) {
			toast.showError(
				new Error(`Extension "${extension.name}" does not have a frontend entry point`),
				'Error loading extension',
			);
			return;
		}

		const basePath = extension.path.replace('n8n.manifest.json', '');
		const mainPath = `${basePath}${extension.setup.frontend?.replace('./', '')}`;

		// Import the extension module
		const extensionModule = await import(mainPath);
		const context = n8n;
		extensionModule.setup(context.n8n.extensionContext);
		extension.initialized = true;
	};

	/**
	 * Option B: Load the extension in an isolated iframe
	 * This is a more secure way to load an extension, but it is more complex.
	 * The extension is loaded in a sandboxed iframe, which means it does not have access to the global scope.
	 * The extension can only communicate with the parent window using postMessage.
	 * @param id
	 * @returns
	 */
	const setupExtensionUsingIframe = async (id: string) => {
		const extension = getExtensionById(id);
		if (!extension || !extension.enabled) return;

		if (!extension.setup.frontend) {
			toast.showError(
				new Error(`Extension "${extension.name}" does not have a frontend entry point`),
				'Error loading extension',
			);
			return;
		}

		const basePath = extension.path.replace('n8n.manifest.json', '');
		const relativePath = `${basePath}${extension.setup.frontend?.replace('./', '')}`;
		const mainPath = new URL(relativePath, window.location.origin).href;

		try {
			// Fetch the extension code
			const response = await fetch(mainPath);
			if (!response.ok) {
				throw new Error(`Failed to fetch extension code: ${response.statusText}`);
			}
			const extensionCode = await response.text();
			let iframe = document.getElementById(EXTENSION_SANDBOX_ID) as HTMLIFrameElement;
			if (!iframe) {
				iframe = document.createElement('iframe');
				iframe.id = EXTENSION_SANDBOX_ID;
				// TODO: Setting 'allow-same-origin' is not secure, we need to find a way to load the extension without it
				iframe.sandbox = 'allow-scripts allow-same-origin';
				iframe.style.display = 'none';
				document.body.appendChild(iframe);
			}
			// Add iframe to the document
			document.body.appendChild(iframe);

			// Set up communication
			const messageHandler = (event: MessageEvent) => {
				if (event.source !== iframe.contentWindow) return;

				const { type, method, args, callId } = event.data;

				// TODO: Whitelist api calls
				if (type === 'API_CALL') {
					console.log(`API call from extension ${id}: ${method}`, args);
					// Call the method on the extension context
					const context = n8n;
					// @ts-expect-error testing
					const result = context.n8n.extensionContext[method](...args);
					// Send the result back to the extension
					if (result instanceof Promise) {
						console.log(`API call from extension ${id}: ${method} is a promise`, args);
						result
							.then((data) => {
								iframe.contentWindow?.postMessage(
									{
										type: 'API_RESPONSE',
										callId,
										result: data,
									},
									'*',
								);
							})
							.catch((error) => {
								iframe.contentWindow?.postMessage(
									{
										type: 'API_ERROR',
										callId,
										error: error.message,
									},
									'*',
								);
							});
					} else {
						iframe.contentWindow?.postMessage(
							{
								type: 'API_RESPONSE',
								callId,
								result,
							},
							'*',
						);
					}
					console.log(`API response to extension ${id}: ${method}`, result);
				} else if (type === 'EXTENSION_LOADED') {
					console.log(`Extension ${id} loaded successfully`);
					extension.initialized = true;
				}
			};

			window.addEventListener('message', messageHandler);
			// extension.messageHandler = messageHandler;

			// Create a blob URL for the extension code
			const blob = new Blob([extensionCode], { type: 'application/javascript' });
			const blobUrl = URL.createObjectURL(blob);

			// Create the iframe content with the extension code loaded via blob URL
			const iframeContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <script type="module">
          // Create API proxy for communication with parent
          const extensionAPI = new Proxy({}, {
            get: (target, prop) => {
              return (...args) => {
                return new Promise((resolve, reject) => {
                  const callId = Date.now() + Math.random();

                  const handler = (event) => {
                    const { type, callId: responseId, result, error } = event.data;
                    if ((type === 'API_RESPONSE' || type === 'API_ERROR') && responseId === callId) {
                      window.removeEventListener('message', handler);

                      if (type === 'API_RESPONSE') {
                        resolve(result);
                      } else {
                        reject(new Error(error));
                      }
                    }
                  };

                  window.addEventListener('message', handler);

                  window.parent.postMessage({
                    type: 'API_CALL',
                    method: prop,
                    args,
                    callId
                  }, '*');
                });
              };
            }
          });

          // Import the extension code from the blob URL
          import('${blobUrl}')
            .then(module => {
              if (typeof module.setup !== 'function') {
                throw new Error('Extension does not export a setup function');
              }

              // Call setup with the API proxy
              module.setup(extensionAPI);

              // Notify parent
              window.parent.postMessage({ type: 'EXTENSION_LOADED', id: '${id}' }, '*');
            })
            .catch(error => {
              console.error('Error loading extension:', error);
              window.parent.postMessage({
                type: 'EXTENSION_ERROR',
                id: '${id}',
                error: error.message
              }, '*');
            });
        </script>
      </head>
      <body></body>
      </html>
    `;

			// Set the iframe content
			const htmlBlob = new Blob([iframeContent], { type: 'text/html' });
			iframe.src = URL.createObjectURL(htmlBlob);

			// Store for cleanup
			// extension.iframe = iframe;
			// extension.blobUrls = [blobUrl, iframe.src];
		} catch (error) {
			toast.showError(error, 'Error loading extension');
			return;
		}

		extension.initialized = true;
	};

	const setupExtension = async (id: string) => {
		switch (setupMethod.value) {
			case 'directImport':
				await setupExtensionUsingDirectImport(id);
				break;
			case 'iframe':
				await setupExtensionUsingIframe(id);
				break;
		}
	};

	return {
		extensions,
		loadExtensions,
		getAllSettingsExtensions,
		getSettingsExtension,
		setupExtension,
		setupMethod,
	};
});
