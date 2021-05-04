import Vue from 'vue';
import VueI18n from 'vue-i18n';
import messages from './locales/en';
import axios from 'axios';

Vue.use(VueI18n);

export const i18n = new VueI18n({
	locale: 'en', // set locale
	fallbackLocale: 'en',
	messages, // set locale messages
});

const loadedLanguages = ['en']; // our default language that is preloaded

function setI18nLanguage (lang: string): string {
	i18n.locale = lang;
	axios.defaults.headers.common['Accept-Language'] = lang;
	document!.querySelector('html')!.setAttribute('lang', lang);
	return lang;
}

export function addNodeTranslations(translations: object) {
	const lang = Object.keys(translations)[0];
	// @ts-ignore
	const messages = translations[lang];
	console.log('ADDING NODE LANGUAGE', lang, messages);
	const newNodesBase = { 'n8n-nodes-base': Object.assign(i18n.messages[lang]['n8n-nodes-base'], messages) };
	i18n.setLocaleMessage(lang, Object.assign(i18n.messages[lang], newNodesBase));
	console.log(i18n.messages);
}

export function loadLanguageAsync(lang: string) {
	// If the same language
	if (i18n.locale === lang) {
		return Promise.resolve(setI18nLanguage(lang));
	}

	// If the language was already loaded
	if (loadedLanguages.includes(lang)) {
		return Promise.resolve(setI18nLanguage(lang));
	}

	// If the language hasn't been loaded yet
	return import(/* webpackChunkName: "locale-[request]" */ `./locales/${lang}`).then(
		messages => {
			i18n.setLocaleMessage(lang, messages.default);
			loadedLanguages.push(lang);
			return setI18nLanguage(lang);
		},
	);
}
