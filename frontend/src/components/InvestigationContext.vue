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
  investigation?: {
    identity?: {
      raw_from: string
      display_name: string
      address: string
      domain: string
      reply_to: { address: string; domain: string }[]
      return_path: { address: string }[]
      anomalies: { code: string; message: string }[]
    }
    routing?: { order: string; hops: NonNullable<Header['received']> }
    urls?: ({
      value: string
      domain: string
      display_texts: string[]
      destination_mismatch: boolean
    } & SignalContext)[]
    attachments?: ({
      index: number
      filename: string
      sha256: string
      static_findings: { key: string; description: string }[]
    } & SignalContext)[]
    authentication?: {
      declared: {
        source: string
        raw: string
        authserv_id: string
        mechanism: string
        result: string
        detail: string
        confidence: string
      }[]
    }
  }
  eml?: {
    header?: Header
    bodies?: { urls?: string[]; domains?: string[]; ip_addresses?: string[] }[]
  }
}
type SignalContext = {
  ioc_id: number | null
  analysis_count: number
  case_count: number
  campaigns: { id: number; name: string }[]
  enrichments: { id: string; provider: string; status: string; summary: string }[]
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
  header = computed(() => parsed.value.eml?.header || {}),
  investigation = computed(() => parsed.value.investigation),
  identity = computed(() => investigation.value?.identity)
const field = (name: string) =>
  Object.entries(header.value.header || {})
    .find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1]
    .join(', ') || '—'
const sender = computed(() => identity.value?.raw_from || header.value.from_ || field('From'))
const address = computed(
  () =>
    identity.value?.address ||
    sender.value.match(/<([^>]+)>/)?.[1] ||
    header.value.from_ ||
    sender.value
)
const senderDomain = computed(
  () => identity.value?.domain || address.value.split('@')[1]?.toLowerCase() || ''
)
const replyDomain = computed(
  () =>
    field('Reply-To')
      .match(/@([^>\s,]+)/)?.[1]
      ?.toLowerCase() || ''
)
const urls = computed(() => [
  ...new Set(parsed.value.eml?.bodies?.flatMap((body) => body.urls || []) || [])
])
const routing = computed(
  () => investigation.value?.routing?.hops || [...(header.value.received || [])].reverse()
)
const urlContexts = computed(
  () =>
    investigation.value?.urls ||
    urls.value.map((value) => ({
      value,
      domain: '',
      display_texts: [],
      destination_mismatch: false,
      ioc_id: null,
      analysis_count: 0,
      case_count: 0,
      campaigns: [],
      enrichments: []
    }))
)
function anomalyLabel(code: string) {
  return t(
    (
      {
        reply_to_domain_differs:
          'Le domaine Reply-To diffère du domaine expéditeur. Vérifiez le contexte avant de conclure.',
        return_path_domain_differs:
          'Le domaine Return-Path diffère du domaine expéditeur. Un service de routage légitime peut expliquer cet écart.',
        display_name_domain_differs:
          'Le nom affiché mentionne un autre domaine que l’adresse expéditeur. Vérifiez l’identité revendiquée.'
      } as Record<string, string>
    )[code] || 'Une incohérence d’identité est déclarée ; vérifiez les en-têtes et le contexte.'
  )
}
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
      <dt>{{ t('Nom affiché') }}</dt>
      <dd>{{ identity?.display_name || '—' }}</dd>
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
    <p v-for="anomaly in identity?.anomalies || []" :key="anomaly.code" class="error">
      {{ anomalyLabel(anomaly.code) }}
    </p>
    <p
      v-if="!identity && senderDomain && replyDomain && senderDomain !== replyDomain"
      class="error"
    >
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
    <dl
      v-for="(claim, index) in investigation?.authentication?.declared || []"
      :key="index"
      class="note"
    >
      <dt>{{ t('Déclaration non vérifiée') }}</dt>
      <dd>{{ claim.mechanism }} · {{ claim.result }}</dd>
      <dt>{{ t('Relais déclarant') }}</dt>
      <dd>{{ claim.authserv_id || '—' }}</dd>
      <dt>{{ t('Source') }}</dt>
      <dd>{{ claim.source }} · {{ claim.detail }}</dd>
    </dl>
    <p v-if="!authHeaders.length">{{ t('Aucun en-tête d’authentification disponible.') }}</p>
    <h2>{{ t('Parcours du message') }}</h2>
    <p class="small muted">
      {{
        t(
          'Du premier au dernier relais déclaré. Les dates et relais reçus ne constituent pas une preuve de confiance.'
        )
      }}
    </p>
    <article v-for="(hop, index) in routing" :key="index" class="timeline">
      <i></i>
      <div>
        <strong>{{ hop.from_?.join(', ') || '—' }} → {{ hop.by?.join(', ') || '—' }}</strong
        ><small
          >{{ hop.date
          }}<template v-if="hop.delay !== undefined && hop.delay !== null">
            · {{ hop.delay }} s</template
          ></small
        >
        <details>
          <summary>{{ t('Source') }}</summary>
          <pre>{{ hop.src }}</pre>
        </details>
      </div>
    </article>
    <h2>{{ t('URLs extraites') }} ({{ urlContexts.length }})</h2>
    <p class="small muted">
      {{
        t('Les destinations sont neutralisées. Aucune ressource distante du message n’est chargée.')
      }}
    </p>
    <article v-for="url in urlContexts" :key="url.value" class="note signal-context">
      <code class="ioc-value">{{ defang(url.value) }}</code>
      <button class="text-link" @click="copy(url.value)">
        {{ copied === url.value ? t('Copié') : t('Copier la valeur neutralisée') }}
      </button>
      <p v-if="url.domain">{{ t('Domaine') }} · {{ defang(url.domain) }}</p>
      <p v-for="(label, index) in url.display_texts" :key="index">
        {{ t('Texte du lien') }} · {{ defang(label) }}
      </p>
      <p v-if="url.destination_mismatch" class="error">
        {{
          t('Le texte du lien et sa destination diffèrent. Vérifiez le contexte avant de conclure.')
        }}
      </p>
      <p v-if="url.ioc_id">
        <a
          :href="'/iocs/' + url.ioc_id"
          @click.exact.prevent="router.push('/iocs/' + url.ioc_id)"
          >{{ t('Voir l’indicateur') }}</a
        >
        · {{ url.analysis_count }} {{ t('Analyses') }} · {{ url.case_count }} {{ t('Dossiers') }}
      </p>
      <p v-for="campaign in url.campaigns" :key="campaign.id">
        <a
          :href="'/campaigns/' + campaign.id"
          @click.exact.prevent="router.push('/campaigns/' + campaign.id)"
          >{{ t('Campagne') }} · {{ campaign.name }}</a
        >
      </p>
      <p v-for="enrichment in url.enrichments" :key="enrichment.id">
        {{ enrichment.provider }} · {{ enrichment.status }} · {{ enrichment.summary }}
      </p>
    </article>
    <template v-if="investigation?.attachments?.length">
      <h2>{{ t('Contexte des pièces jointes') }}</h2>
      <article
        v-for="attachment in investigation.attachments"
        :key="attachment.index"
        class="note signal-context"
      >
        <h3>{{ attachment.filename }}</h3>
        <code class="hash">{{ attachment.sha256 }}</code>
        <p v-if="attachment.ioc_id">
          <a
            :href="'/iocs/' + attachment.ioc_id"
            @click.exact.prevent="router.push('/iocs/' + attachment.ioc_id)"
            >{{ t('Voir l’indicateur') }}</a
          >
          · {{ attachment.analysis_count }} {{ t('Analyses') }} · {{ attachment.case_count }}
          {{ t('Dossiers') }}
        </p>
        <p v-for="campaign in attachment.campaigns" :key="campaign.id">
          <a
            :href="'/campaigns/' + campaign.id"
            @click.exact.prevent="router.push('/campaigns/' + campaign.id)"
            >{{ t('Campagne') }} · {{ campaign.name }}</a
          >
        </p>
        <p v-for="finding in attachment.static_findings" :key="finding.key">
          {{ finding.key }} · {{ finding.description }}
        </p>
        <p v-for="enrichment in attachment.enrichments" :key="enrichment.id">
          {{ enrichment.provider }} · {{ enrichment.status }} · {{ enrichment.summary }}
        </p>
      </article>
    </template>
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
