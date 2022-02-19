import { getCollectionById, getTemplateById, getTemplates } from '@/api/templates';
import { ActionContext, Module } from 'vuex';
import {
	IRootState,
	IN8nCollectionResponse,
	IN8nCollection,
	IN8nSearchResponse,
	IN8nSearchData,
	IN8nTemplate,
	IN8nTemplateResponse,
	ITemplateCategory,
	ITemplateCollection,
	ITemplateState,
} from '../Interface';

import Vue from 'vue';

const module: Module<ITemplateState, IRootState> = {
	namespaced: true,
	state: {
		categories: [],
		collection: {} as ITemplateCollection,
		collections: [],
		templates: [],
		template: {} as IN8nTemplate,
		templateSessionId: null,
		totalworkflow: null,
	},
	getters: {
		getCategories(state: ITemplateState) {
			return state.categories;
		},
		getCollection(state: ITemplateState) {
			return state.collection;
		},
		getCollections(state: ITemplateState) {
			return state.collections;
		},
		getTemplates(state: ITemplateState) {
			return state.templates;
		},
		getTemplate(state: ITemplateState) {
			return state.template;
		},
		getTemplateSessionId(state: ITemplateState) {
			return state.templateSessionId;
		},
		getTotalWorkflows(state: ITemplateState) {
			return state.totalworkflow;
		},
	},
	mutations: {
		appendWorkflows(state: ITemplateState, templates: IN8nTemplate[]) {
			Vue.set(state, 'templates', state.templates.concat(templates));
		},
		setCategories(state: ITemplateState, categories: ITemplateCategory[]) {
			Vue.set(state, 'categories', categories);
		},
		setCollection(state: ITemplateState, collection: IN8nCollection) {
			Vue.set(state, 'collection', collection);
		},
		setCollections(state: ITemplateState, collections: ITemplateCollection[]) {
			Vue.set(state, 'collections', collections);
		},
		setTemplate(state: ITemplateState, template: IN8nTemplate) {
			Vue.set(state, 'template', template);
		},
		setTemplateSessionId(state: ITemplateState, sessionId: number) {
			state.templateSessionId = sessionId;
		},
		setTotalWorkflows(state: ITemplateState, totalworkflow: number) {
			state.totalworkflow = totalworkflow;
		},
		setWorkflows(state: ITemplateState, templates: IN8nTemplate[]) {
			Vue.set(state, 'templates', templates);
		},
	},
	actions: {
		async getCollectionById(context: ActionContext<ITemplateState, IRootState>, collectionId: string) {
			const apiEndpoint: string = context.rootGetters['settings/templatesHost'];
			const response: IN8nCollectionResponse = await getCollectionById(collectionId, apiEndpoint);
			const collection: IN8nCollection = response.data.collection;

			context.commit('setCollection', collection);
			return collection;
		},
		async getTemplateById(context: ActionContext<ITemplateState, IRootState>, templateId: string) {
			const apiEndpoint: string = context.rootGetters['settings/templatesHost'];
			const response: IN8nTemplateResponse = await getTemplateById(templateId, apiEndpoint);
			const template: IN8nTemplate = response.data.workflow;

			context.commit('setTemplate', template);
			return template;
		},
		async getSearchResults(context: ActionContext<ITemplateState, IRootState>, { numberOfResults = 10, search , category, skip = 0, fetchCategories = false }) {
			const searchQuery = search.length || category ? true : false;
			const allData = fetchCategories ? fetchCategories : !searchQuery;

			const apiEndpoint: string = context.rootGetters['settings/templatesHost'];
			const payload: IN8nSearchResponse = await getTemplates(numberOfResults, skip, category, search, allData, !allData, apiEndpoint);
			const results : IN8nSearchData = payload.data;
			if (allData) {
				const categories = results.categories.map((category: ITemplateCategory) => {
					category.selected = false;
					return category;
				});
				context.commit('setCategories', categories);
			}

			if (skip) {
				context.commit('appendWorkflows', results.workflows);
			} else {
				context.commit('setCollections', results.collections);
				context.commit('setTotalWorkflows', results.totalworkflow);
				context.commit('setWorkflows', results.workflows);
			}
			return results;
		},
		async setTemplateSessionId(context: ActionContext<ITemplateState, IRootState>, sessionId: number) {
			context.commit('setTemplateSessionId', sessionId);
		},
	},
};

export default module;
