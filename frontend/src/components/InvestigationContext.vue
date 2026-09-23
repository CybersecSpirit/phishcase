<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { t } from '@/i18n'
import router from '@/router'
import { defang, emptyPage, type Page, pageQuery, type Request } from '@/workspace'

import PaginationControls from './PaginationControls.vue'
type Header = {
  from_?: string
  message_id?: string
  header?: Record<string, (string | number)[]>
  received?: { from_?: string[]; by?: string[]; date?: string; delay?: number; src?: string }[]
}
type Result = {
  eml?: {
    header?: Header
    bodies?: { urls?: string[]; domains?: string[]; ip_addresses?: string[] }[]
  }
}
type Similar = {
  id: string
  case_id: number
  subject: string
  filename: string
  reasons: { kind: string; value: string; label: string }[]
}
const props = defineProps<{
  analysisId: string
  result: Record<string, unknown>
  request: Request
}>()
const parsed = computed(() => props.result as Result),
  header = computed(() => parsed.value.eml?.header || {})
const field = (name: string) =>
  Object.entries(header.value.header || {})
    .find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1]
    .join(', ') || '—'
const sender = computed(() => header.value.from_ || field('From'))
const address = computed(() => sender.value.match(/<([^>]+)>/)?.[1] || sender.value)
const senderDomain = computed(() => address.value.split('@')[1]?.toLowerCase() || '')
const replyDomain = computed(
  () =>
    field('Reply-To')
      .match(/@([^>\s,]+)/)?.[1]
      ?.toLowerCase() || ''
)
const urls = computed(() => [
  ...new Set(parsed.value.eml?.bodies?.flatMap((body) => body.urls || []) || [])
])
const authHeaders = computed(() =>
  Object.entries(header.value.header || {}).filter(([key]) =>
    [
      'authentication-results',
      'received-spf',
      'arc-authentication-results',
      'dkim-signature'
    ].includes(key.toLowerCase())
  )
)
const similarities = ref(emptyPage<Similar>()),
  busy = ref(false),
  error = ref(''),
  copied = ref('')
async function load(page = 1) {
  busy.value = true
  error.value = ''
  try {
    similarities.value = await props.request<Page<Similar>>(
      '/analyses/' + props.analysisId + '/similarities?' + pageQuery(page)
    )
  } catch (e) {
    error.value = e instanceof Error ? e.message : t('Erreur inattendue')
  } finally {
    busy.value = false
  }
}
async function copy(value: string) {
  try {
    await navigator.clipboard.writeText(defang(value))
    copied.value = value
  } catch {
    error.value = t('La copie est indisponible. Sélectionnez la valeur neutralisée.')
  }
}
watch(
  () => props.analysisId,
  () => load(),
  { immediate: true }
)
</script>
<template>
  <section class="investigation-context">
    <h2>{{ t('Identité et en-têtes') }}</h2>
    <dl>
      <dt>{{ t('From affiché') }}</dt>
      <dd>{{ sender }}</dd>
      <dt>{{ t('Adresse expéditeur') }}</dt>
      <dd>{{ defang(address) }}</dd>
      <dt>Reply-To</dt>
      <dd>{{ defang(field('Reply-To')) }}</dd>
      <dt>Return-Path</dt>
      <dd>{{ defang(field('Return-Path')) }}</dd>
      <dt>Message-ID</dt>
      <dd>{{ header.message_id || field('Message-ID') }}</dd>
      <dt>{{ t('Domaine expéditeur') }}</dt>
      <dd>{{ defang(senderDomain) || '—' }}</dd>
    </dl>
    <p v-if="senderDomain && replyDomain && senderDomain !== replyDomain" class="error">
      {{
        t(
          'Le domaine Reply-To diffère du domaine expéditeur. Vérifiez le contexte avant de conclure.'
        )
      }}
    </p>
    <h2>{{ t('Authentification déclarée') }}</h2>
    <p class="small muted">
      {{
        t(
          'Ces en-têtes proviennent du message reçu et peuvent être falsifiés. Seul un relais de confiance permet de valider leur provenance ; aucun résultat SPF/DMARC n’est déduit de leur seule présence.'
        )
      }}
    </p>
    <article v-for="[name, values] in authHeaders" :key="name" class="note">
      <strong>{{ name }}</strong>
      <pre>{{ values.join('\n') }}</pre>
    </article>
    <p v-if="!authHeaders.length">{{ t('Aucun en-tête d’authentification disponible.') }}</p>
    <h2>{{ t('Parcours du message') }}</h2>
    <p class="small muted">
      {{
        t(
          'Ordre chronologique inversé des en-têtes Received. Les relais déclarés ne constituent pas une preuve de confiance.'
        )
      }}
    </p>
    <article
      v-for="(hop, index) in [...(header.received || [])].reverse()"
      :key="index"
      class="timeline"
    >
      <i></i>
      <div>
        <strong>{{ hop.from_?.join(', ') || '—' }} → {{ hop.by?.join(', ') || '—' }}</strong
        ><small
          >{{ hop.date
          }}<template v-if="hop.delay !== undefined"> · {{ hop.delay }} s</template></small
        >
        <details>
          <summary>{{ t('Source') }}</summary>
          <pre>{{ hop.src }}</pre>
        </details>
      </div>
    </article>
    <h2>{{ t('URLs extraites') }} ({{ urls.length }})</h2>
    <p class="small muted">
      {{
        t('Les destinations sont neutralisées. Aucune ressource distante du message n’est chargée.')
      }}
    </p>
    <article v-for="url in urls" :key="url" class="note">
      <code class="ioc-value">{{ defang(url) }}</code>
      <button class="text-link" @click="copy(url)">
        {{ copied === url ? t('Copié') : t('Copier la valeur neutralisée') }}
      </button>
    </article>
    <h2>{{ t('Emails similaires') }} ({{ similarities.total }})</h2>
    <p class="small muted">
      {{
        t(
          'Liens suggérés à partir d’indicateurs partagés. Aucun dossier n’est fusionné automatiquement.'
        )
      }}
    </p>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <article v-for="item in similarities.items" :key="item.id" class="note">
      <a
        :href="'/analyses/' + item.id"
        @click.exact.prevent="router.push('/analyses/' + item.id)"
        >{{ item.subject || item.filename }}</a
      >
      <p v-for="reason in item.reasons" :key="reason.kind + reason.value">
        {{ t('Correspondance exacte : {kind}', { kind: reason.kind }) }} ·
        <code>{{ defang(reason.value) }}</code>
      </p>
    </article>
    <PaginationControls v-bind="similarities" :busy="busy" @change="load" />
  </section>
</template>
