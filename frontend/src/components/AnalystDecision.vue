<script setup lang="ts">
import { ref, watch } from 'vue'

import { errorMessage } from '@/errors'
import { t } from '@/i18n'
import { emptyPage, type Page, pageQuery, type Request } from '@/workspace'

import PaginationControls from './PaginationControls.vue'
type Decision = {
  id: number
  verdict: string | null
  confidence: number
  justification: string
  username: string
  created_at: string
  action: string
}
const props = defineProps<{ analysisId: string; request: Request; canWrite: boolean }>()
const choices = [
  'legitimate',
  'spam',
  'phishing',
  'credential_phishing',
  'malware_delivery',
  'bec_fraud',
  'suspicious',
  'inconclusive'
]
const names: Record<string, string> = {
  legitimate: 'Légitime',
  spam: 'Spam',
  phishing: 'Phishing',
  credential_phishing: 'Vol d’identifiants',
  malware_delivery: 'Distribution de malware',
  bec_fraud: 'Fraude BEC',
  suspicious: 'Suspect',
  inconclusive: 'Non concluant'
}
const current = ref<Decision | null>(null),
  history = ref(emptyPage<Decision>()),
  verdict = ref('inconclusive'),
  confidence = ref(50),
  justification = ref(''),
  error = ref(''),
  busy = ref(false)
async function load(page = 1) {
  const [decision, events] = await Promise.all([
    props.request<{ current: Decision | null }>('/analyses/' + props.analysisId + '/decision'),
    props.request<Page<Decision>>(
      '/analyses/' + props.analysisId + '/decision/history?' + pageQuery(page)
    )
  ])
  current.value = decision.current
  history.value = events
}
async function run(action: () => Promise<unknown>) {
  busy.value = true
  error.value = ''
  try {
    await action()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
async function save(reopen = false) {
  await run(async () => {
    await props.request(
      '/analyses/' + props.analysisId + '/decision' + (reopen ? '/reopen' : ''),
      reopen ? 'POST' : 'PUT',
      reopen
        ? { justification: justification.value }
        : {
            verdict: verdict.value,
            confidence: Number(confidence.value),
            justification: justification.value
          }
    )
    justification.value = ''
    await load()
  })
}
watch(
  () => props.analysisId,
  () => run(load),
  { immediate: true }
)
</script>
<template>
  <section class="panel human-decision">
    <h2>{{ t('Décision analyste') }}</h2>
    <p class="small muted">
      {{ t('Cette décision humaine est indépendante des résultats automatiques.') }}
    </p>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <article v-if="current" class="note">
      <strong
        >{{ t(names[current.verdict || ''] || current.verdict || '') }} ·
        {{ current.confidence }} %</strong
      >
      <p>{{ current.justification }}</p>
      <small>{{ current.username }} · {{ current.created_at }}</small>
    </article>
    <p v-else>{{ t('Aucune conclusion humaine active.') }}</p>
    <form v-if="canWrite" class="form-grid" @submit.prevent="save()">
      <div class="inline-fields">
        <label
          >{{ t('Verdict')
          }}<select v-model="verdict">
            <option v-for="choice in choices" :key="choice" :value="choice">
              {{ t(names[choice] || choice) }}
            </option>
          </select></label
        >
        <label
          >{{ t('Confiance (%)')
          }}<input v-model="confidence" type="number" min="0" max="100" required
        /></label>
      </div>
      <label
        >{{ t('Justification')
        }}<textarea v-model="justification" required maxlength="20000" rows="3"></textarea>
      </label>
      <div>
        <button class="primary" :disabled="busy">{{ t('Enregistrer la décision') }}</button>
        <button
          v-if="current"
          type="button"
          class="secondary"
          :disabled="busy || !justification.trim()"
          @click="save(true)"
        >
          {{ t('Rouvrir avec cette justification') }}
        </button>
      </div>
    </form>
    <details>
      <summary>{{ t('Historique des décisions') }} ({{ history.total }})</summary>
      <article v-for="event in history.items" :key="event.id" class="note">
        <strong>{{
          event.action === 'reopened'
            ? t('Investigation rouverte')
            : t(names[event.verdict || ''] || event.verdict || '')
        }}</strong>
        <p>{{ event.justification }}</p>
        <small>{{ event.username }} · {{ event.created_at }}</small>
      </article>
      <PaginationControls v-bind="history" :busy="busy" @change="(page) => run(() => load(page))" />
    </details>
  </section>
</template>
