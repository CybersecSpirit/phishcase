<script setup lang="ts">
import { ref, watch } from 'vue'

import { errorMessage } from '@/errors'
import { t } from '@/i18n'
import router from '@/router'
import { type Page, pageQuery, type Request } from '@/workspace'

import PaginationControls from './PaginationControls.vue'
type Campaign = { id: number; name: string; revision: number; status: string }
const props = defineProps<{ analysisIds: string[]; request: Request; canWrite: boolean }>()
const query = ref(''),
  options = ref<Page<Campaign> | null>(null),
  target = ref<number | null>(null),
  name = ref(''),
  error = ref(''),
  busy = ref(false)
async function load(page = 1) {
  busy.value = true
  error.value = ''
  try {
    options.value = await props.request('/campaigns?' + pageQuery(page, { q: query.value }))
    target.value = null
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
async function save(create = false) {
  busy.value = true
  error.value = ''
  try {
    const campaign = options.value?.items.find((c) => c.id === target.value)
    if (!create && !campaign) return
    const result = await props.request<Campaign>(
      create ? '/campaigns' : '/campaigns/' + campaign!.id + '/emails',
      'POST',
      create
        ? { name: name.value, analysis_ids: props.analysisIds }
        : { analysis_ids: props.analysisIds, revision: campaign!.revision }
    )
    await router.push('/campaigns/' + result.id)
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
watch(
  () => props.analysisIds.join(','),
  () => {
    if (props.canWrite && props.analysisIds.length) void load()
  },
  { immediate: true }
)
</script>
<template>
  <section v-if="canWrite && analysisIds.length" class="panel campaign-picker">
    <h2>{{ analysisIds.length }} {{ t('email(s) sélectionné(s)') }}</h2>
    <p class="muted small">
      {{ t('Le rattachement est facultatif. Chaque email conserve son analyse et son verdict.') }}
    </p>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <form class="filters" @submit.prevent="load()">
      <input
        v-model="query"
        :placeholder="t('Rechercher une campagne')"
        :aria-label="t('Rechercher une campagne')"
      />
      <button class="secondary" :disabled="busy">{{ t('Rechercher') }}</button>
    </form>
    <form class="filters" @submit.prevent="save()">
      <select v-model="target" :aria-label="t('Campagne')">
        <option :value="null">{{ t('Choisir une campagne') }}</option>
        <option
          v-for="c in options?.items.filter((c) => c.status !== 'closed')"
          :key="c.id"
          :value="c.id"
        >
          {{ c.name }}
        </option>
      </select>
      <button class="secondary" :disabled="busy || !target">{{ t('Rattacher les emails') }}</button>
    </form>
    <PaginationControls v-if="options" v-bind="options" :busy="busy" @change="load" />
    <form class="filters" @submit.prevent="save(true)">
      <input
        v-model="name"
        :placeholder="t('Nom de la nouvelle campagne')"
        :aria-label="t('Nom de la nouvelle campagne')"
        required
        maxlength="200"
      />
      <button class="primary" :disabled="busy">
        {{ t('Créer une campagne avec ces emails') }}
      </button>
    </form>
  </section>
</template>
