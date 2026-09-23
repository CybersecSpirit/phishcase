<script setup lang="ts">
import { ref, watch } from 'vue'

import { t } from '@/i18n'
import router from '@/router'
import { emptyPage, type Page, pageQuery, type Request } from '@/workspace'

import PaginationControls from './PaginationControls.vue'
type Hit = { type: string; id: string | number; title: string; subtitle: string; url: string }
const props = defineProps<{ request: Request }>()
const query = ref(String(router.currentRoute.value.query.q || '')),
  kind = ref(String(router.currentRoute.value.query.type || 'all')),
  results = ref(emptyPage<Hit>()),
  busy = ref(false),
  error = ref('')
async function load(page = 1) {
  busy.value = true
  error.value = ''
  try {
    results.value = await props.request<Page<Hit>>(
      '/search?' + pageQuery(page, { q: query.value, type: kind.value })
    )
  } catch (e) {
    error.value = e instanceof Error ? e.message : t('Erreur inattendue')
  } finally {
    busy.value = false
  }
}
async function search(page = 1) {
  await router.push({ path: '/search', query: { q: query.value, type: kind.value, page } })
}
watch(
  () => router.currentRoute.value.fullPath,
  () => {
    if (router.currentRoute.value.path !== '/search') return
    query.value = String(router.currentRoute.value.query.q || '')
    kind.value = String(router.currentRoute.value.query.type || 'all')
    void load(Number(router.currentRoute.value.query.page || 1))
  },
  { immediate: true }
)
const pathFor = (hit: Hit) =>
  (({ case: '/cases/', analysis: '/analyses/', ioc: '/iocs/', campaign: '/campaigns/' })[
    hit.type
  ] || '/search?unknown=') + encodeURIComponent(hit.id)
</script>
<template>
  <section class="panel">
    <form class="filters" @submit.prevent="search()">
      <input
        v-model="query"
        :aria-label="t('Recherche globale')"
        :placeholder="t('Sujet, expéditeur, URL, hash, campagne…')"
        minlength="2"
        required
      /><select v-model="kind" :aria-label="t('Type de résultat')">
        <option value="all">{{ t('Tous les types') }}</option>
        <option value="case">{{ t('Dossiers') }}</option>
        <option value="analysis">{{ t('Analyses') }}</option>
        <option value="ioc">{{ t('Indicateurs') }}</option>
        <option value="campaign">{{ t('Campagnes') }}</option></select
      ><button class="primary" :disabled="busy">{{ t('Rechercher') }}</button>
    </form>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <p v-if="!busy && !results.total">{{ t('Aucun résultat trouvé.') }}</p>
    <a
      v-for="hit in results.items"
      :key="hit.type + hit.id"
      :href="pathFor(hit)"
      class="case-row"
      @click.exact.prevent="router.push(pathFor(hit))"
      ><span class="badge">{{ hit.type }}</span>
      <div>
        <strong>{{ hit.title }}</strong
        ><small>{{ hit.subtitle }}</small>
      </div></a
    >
    <PaginationControls v-bind="results" :busy="busy" @change="search" />
  </section>
</template>
