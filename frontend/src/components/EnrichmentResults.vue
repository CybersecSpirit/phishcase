<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import PaginationControls from '@/components/PaginationControls.vue'
import { t } from '@/i18n'
import { defang, type Request } from '@/workspace'
type Provider = {
  name: string
  configured: boolean
  lookup_allowed: boolean
  lookup_kinds: string[]
  submission_allowed: { file: boolean; url: boolean }
  health: string
  secret_source?: 'tenant' | 'environment'
  last_healthcheck?: { status: string; detail?: string; summary?: string; checked_at: string }
  visibility_default?: string
}
type Integration = {
  mode: string
  providers: Provider[]
  dkim?: { enabled: boolean; allowed: boolean; mode: string }
}
type Enrichment = {
  id: number
  provider: string
  action: string
  target: { kind: string; value: string }
  status: string
  malicious: number
  suspicious: number
  harmless: number
  unknown: number
  summary: string
  external_url?: string
  first_seen?: string
  file_type?: string
  metadata: Record<string, unknown>
  created_at: string
}
type Result = {
  eml?: {
    attachments?: { filename: string; hash: { sha256: string } }[]
    bodies?: { urls?: string[]; domains?: string[]; ip_addresses?: string[] }[]
  }
}
const props = defineProps<{
  request: Request
  analysisId?: string
  result?: Record<string, unknown>
  canWrite?: boolean
  admin?: boolean
  settingsUrl?: string
}>()
const config = ref<Integration | null>(null),
  items = ref<Enrichment[]>([]),
  error = ref(''),
  message = ref(''),
  busy = ref(false),
  provider = ref('virustotal'),
  target = ref(''),
  submission = ref(''),
  visibility = ref('private'),
  confirmed = ref(false)
const submissionRequestId = ref('')
const dkimConfirmed = ref(false)
const dkimRequestId = ref('')
const enrichmentPage = ref(1)
const enrichmentTotal = ref(0)
const enrichmentPageSize = 50
const urlscanFields: [string, string][] = [
  ['title', 'Titre de la page'],
  ['domain', 'Domaine'],
  ['ip', 'Adresse IP'],
  ['country', 'Pays'],
  ['score', 'Score provider'],
  ['visibility', 'Visibilité']
]
function resultLabel(value: string) {
  return t(
    (
      {
        error: 'Erreur',
        reachable: 'Accessible',
        configured: 'Configuré',
        unconfigured: 'Non configuré',
        valid: 'Signature valide',
        invalid: 'Signature invalide',
        unsigned: 'Aucune signature',
        unavailable: 'Indisponible'
      } as Record<string, string>
    )[value] || value
  )
}
const parsed = computed(() => props.result as Result | undefined)
const targets = computed(() => {
  const map = new Map<string, { kind: string; value: string }>()
  for (const body of parsed.value?.eml?.bodies || [])
    for (const [kind, values] of [
      ['url', body.urls],
      ['domain', body.domains],
      ['ip', body.ip_addresses]
    ] as [string, string[] | undefined][])
      for (const value of values || []) map.set(kind + ':' + value, { kind, value })
  for (const file of parsed.value?.eml?.attachments || [])
    map.set('sha256:' + file.hash.sha256, { kind: 'sha256', value: file.hash.sha256 })
  return [...map.values()]
})
const chosen = computed(() => config.value?.providers.find((item) => item.name === provider.value))
const lookupTargets = computed(() =>
  targets.value.filter((item) => chosen.value?.lookup_kinds.includes(item.kind))
)
const submissionTargets = computed(() => [
  ...(chosen.value?.submission_allowed.url
    ? targets.value
        .filter((item) => item.kind === 'url')
        .map((item) => ({
          key: 'url:' + item.value,
          label: defang(item.value),
          kind: 'url',
          value: item.value,
          index: undefined
        }))
    : []),
  ...(chosen.value?.submission_allowed.file
    ? (parsed.value?.eml?.attachments || []).map((item, index) => ({
        key: 'file:' + index,
        label: item.filename,
        kind: 'file',
        value: undefined,
        index
      }))
    : [])
])
async function run(action: () => Promise<unknown>) {
  busy.value = true
  error.value = ''
  message.value = ''
  try {
    await action()
  } catch (e) {
    error.value = e instanceof Error ? e.message : t('Erreur inattendue')
  } finally {
    busy.value = false
  }
}
async function load() {
  config.value = await props.request<Integration>('/integrations')
  await loadEnrichments()
}
async function loadEnrichments(page = 1) {
  if (props.analysisId) {
    const result = await props.request<{ items: Enrichment[]; total: number }>(
      '/analyses/' +
        props.analysisId +
        '/enrichments?limit=' +
        enrichmentPageSize +
        '&offset=' +
        (page - 1) * enrichmentPageSize
    )
    items.value = result.items
    enrichmentTotal.value = result.total
    enrichmentPage.value = page
  }
}
async function verifyDkim() {
  if (!dkimConfirmed.value || !config.value?.dkim?.allowed) return
  await run(async () => {
    await props.request('/analyses/' + props.analysisId + '/dkim', 'POST', {
      confirm: true,
      request_id: dkimRequestId.value || (dkimRequestId.value = crypto.randomUUID())
    })
    dkimConfirmed.value = false
    dkimRequestId.value = ''
    await loadEnrichments()
  })
}
function screenshotLink(value: unknown) {
  return typeof value === 'string' &&
    /^https:\/\/urlscan\.io\/screenshots\/[0-9a-f-]{36}\.png$/.test(value)
    ? value
    : undefined
}
async function lookup() {
  await run(async () => {
    const item = lookupTargets.value.find((item) => item.kind + ':' + item.value === target.value)
    if (!item) return
    await props.request('/analyses/' + props.analysisId + '/enrichments/lookup', 'POST', {
      provider: provider.value,
      ...item
    })
    await load()
  })
}
async function submit() {
  if (!confirmed.value) return
  await run(async () => {
    const item = submissionTargets.value.find((item) => item.key === submission.value)
    if (!item) return
    await props.request('/analyses/' + props.analysisId + '/enrichments/submit', 'POST', {
      provider: provider.value,
      kind: item.kind,
      value: item.value,
      attachment_index: item.index,
      visibility: visibility.value,
      confirm: true,
      request_id: submissionRequestId.value || (submissionRequestId.value = crypto.randomUUID())
    })
    confirmed.value = false
    submissionRequestId.value = ''
    await load()
  })
}
async function poll(id: number) {
  await run(async () => {
    await props.request('/analyses/' + props.analysisId + '/enrichments/' + id + '/poll', 'POST')
    await load()
  })
}
async function health(name: string) {
  await run(async () => {
    const result = await props.request<{ status?: string; summary?: string }>(
      '/integrations/' + name + '/health',
      'POST'
    )
    message.value = result.summary || result.status || t('Vérification terminée')
    await load()
  })
}
function safeProviderLink(value?: string) {
  if (!value) return undefined
  try {
    const url = new URL(value)
    return url.protocol === 'https:' &&
      ['virustotal.com', 'www.virustotal.com', 'urlscan.io'].includes(url.hostname)
      ? url.href
      : undefined
  } catch {
    return undefined
  }
}
watch(
  () => props.analysisId,
  () => {
    dkimConfirmed.value = false
    dkimRequestId.value = ''
    return run(load)
  },
  { immediate: true }
)
watch([provider, submission, visibility], () => {
  submissionRequestId.value = ''
})
watch(provider, () => {
  target.value = ''
  submission.value = ''
  confirmed.value = false
  visibility.value = 'private'
})
</script>
<template>
  <section class="panel enrichment-panel">
    <h2>{{ t('Enrichissements externes') }}</h2>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <p v-if="message" role="status">{{ message }}</p>
    <template v-if="config"
      ><p>
        {{ t('Connectivité') }}: <strong>{{ config.mode }}</strong>
      </p>
      <p class="small muted">
        {{
          t(
            'Les clés et licences sont fournies par votre organisation. Un lookup ne soumet jamais le fichier.'
          )
        }}
      </p>
      <div v-if="!analysisId">
        <article v-for="item in config.providers" :key="item.name" class="note">
          <strong>{{ item.name }}</strong>
          <p>
            {{ item.configured ? t('Configuré') : t('Non configuré') }} · {{ t('Lookup') }}:
            {{ item.lookup_allowed ? t('Autorisé') : t('Bloqué') }} ·
            {{ t('Soumission de fichiers') }}:
            {{ item.submission_allowed.file ? t('Autorisée') : t('Bloquée') }} ·
            {{ t('Soumission d’URLs') }}:
            {{ item.submission_allowed.url ? t('Autorisée') : t('Bloquée') }}
          </p>
          <dl v-if="item.last_healthcheck" class="integration-health">
            <dt>{{ t('Dernier contrôle') }}</dt>
            <dd>{{ item.last_healthcheck.checked_at }}</dd>
            <dt>{{ t('Santé du provider') }}</dt>
            <dd>{{ resultLabel(item.last_healthcheck.status) }}</dd>
            <dt v-if="item.last_healthcheck.detail || item.last_healthcheck.summary">
              {{
                item.last_healthcheck.status === 'error'
                  ? t('Dernière erreur')
                  : t('Détail du contrôle')
              }}
            </dt>
            <dd v-if="item.last_healthcheck.detail || item.last_healthcheck.summary">
              {{ item.last_healthcheck.detail || item.last_healthcheck.summary }}
            </dd>
          </dl>
          <p v-else class="small muted">{{ t('Aucun contrôle enregistré.') }}</p>
          <button
            v-if="admin"
            class="secondary"
            :disabled="busy || config.mode === 'offline' || !item.configured"
            @click="health(item.name)"
          >
            {{ t('Tester la connexion au provider') }}
          </button>
        </article>
        <p v-if="config.providers.some((item) => item.secret_source === 'tenant')">
          {{
            t('Les clés et autorisations sont gérées dans les paramètres de votre organisation.')
          }}
          <a v-if="admin && settingsUrl" :href="settingsUrl">{{ t('Gérer les intégrations') }} →</a>
        </p>
        <p v-else>
          {{
            t(
              'Configurez les providers et les autorisations dans les variables du déploiement. Les secrets ne sont jamais affichés ici.'
            )
          }}
        </p>
      </div>
      <template v-else
        ><template v-if="canWrite"
          ><label
            >{{ t('Provider')
            }}<select v-model="provider">
              <option v-for="item in config.providers" :key="item.name" :value="item.name">
                {{ item.name }}
              </option>
            </select></label
          >
          <form class="filters" @submit.prevent="lookup">
            <select v-model="target" required :aria-label="t('Indicateur à rechercher')">
              <option disabled value="">{{ t('Choisir un indicateur') }}</option>
              <option
                v-for="item in lookupTargets"
                :key="item.kind + item.value"
                :value="item.kind + ':' + item.value"
              >
                {{ item.kind }} · {{ defang(item.value) }}
              </option></select
            ><button class="secondary" :disabled="busy || !chosen?.lookup_allowed || !target">
              {{ t('Lookup de réputation') }}
            </button>
          </form>
          <details v-if="submissionTargets.length">
            <summary>{{ t('Soumettre explicitement une preuve au provider') }}</summary>
            <form class="form-grid" @submit.prevent="submit">
              <p class="error">
                {{
                  t(
                    'Cette action transmet la preuve sélectionnée à un service tiers selon la politique administrateur.'
                  )
                }}
              </p>
              <label
                >{{ t('Preuve')
                }}<select v-model="submission" required>
                  <option disabled value="">{{ t('Choisir une preuve') }}</option>
                  <option v-for="item in submissionTargets" :key="item.key" :value="item.key">
                    {{ item.label }}
                  </option>
                </select></label
              ><label v-if="provider === 'urlscan'"
                >{{ t('Visibilité')
                }}<select v-model="visibility">
                  <option value="private">{{ t('Privée') }}</option>
                  <option value="unlisted">{{ t('Non listée') }}</option>
                  <option value="public">{{ t('Publique') }}</option>
                </select></label
              ><label class="security-check"
                ><input v-model="confirmed" type="checkbox" required />{{
                  t('J’autorise l’envoi de cette preuve au provider sélectionné.')
                }}</label
              ><button class="primary" :disabled="busy || !confirmed || !submission">
                {{ t('Soumettre la preuve') }}
              </button>
            </form>
          </details></template
        >
        <section v-if="config.dkim" class="note dkim-check">
          <h3>{{ t('Vérifier la signature DKIM') }}</h3>
          <p>
            {{
              t(
                'Les domaines de signature sont transmis au résolveur DNS configuré. Le message reste local. Cette vérification est distincte des déclarations des en-têtes.'
              )
            }}
          </p>
          <p v-if="!config.dkim.allowed" class="small muted">
            {{ t('La vérification DNS DKIM est désactivée par la politique de connectivité.') }}
          </p>
          <form v-if="canWrite" @submit.prevent="verifyDkim">
            <label class="security-check"
              ><input v-model="dkimConfirmed" type="checkbox" :disabled="!config.dkim.allowed" />{{
                t('J’autorise cette consultation DNS explicite.')
              }}</label
            >
            <button class="secondary" :disabled="busy || !config.dkim.allowed || !dkimConfirmed">
              {{ t('Vérifier DKIM') }}
            </button>
          </form>
        </section>
        <p v-if="!items.length" class="small muted">{{ t('Aucun enrichissement enregistré.') }}</p>
        <article v-for="item in items" :key="item.id" class="note">
          <strong>{{ item.provider }} · {{ item.action }} · {{ item.status }}</strong>
          <p class="hash">{{ defang(item.target.value) }}</p>
          <p>{{ item.summary }}</p>
          <dl>
            <dt>{{ t('Malveillants') }}</dt>
            <dd>{{ item.malicious ?? '—' }}</dd>
            <dt>{{ t('Suspects') }}</dt>
            <dd>{{ item.suspicious ?? '—' }}</dd>
            <dt>{{ t('Inoffensifs déclarés') }}</dt>
            <dd>{{ item.harmless ?? '—' }}</dd>
            <dt>{{ t('Inconnus') }}</dt>
            <dd>{{ item.unknown ?? '—' }}</dd>
          </dl>
          <small>{{ item.first_seen }} · {{ item.file_type }} · {{ item.created_at }}</small>
          <section v-if="item.provider === 'urlscan'" class="urlscan-details">
            <h3>{{ t('Observation urlscan') }}</h3>
            <dl>
              <template v-for="[key, label] in urlscanFields" :key="key">
                <dt>{{ t(label) }}</dt>
                <dd>
                  {{
                    typeof item.metadata?.[key] === 'string'
                      ? defang(String(item.metadata[key]))
                      : (item.metadata?.[key] ?? '—')
                  }}
                </dd>
              </template>
            </dl>
            <template
              v-if="Array.isArray(item.metadata?.categories) && item.metadata.categories.length"
            >
              <h4>{{ t('Catégories') }}</h4>
              <ul>
                <li v-for="(category, index) in item.metadata.categories" :key="index">
                  {{ category }}
                </li>
              </ul>
            </template>
            <template
              v-if="
                Array.isArray(item.metadata?.redirect_chain) && item.metadata.redirect_chain.length
              "
            >
              <h4>{{ t('Redirections observées') }}</h4>
              <ol>
                <li v-for="(url, index) in item.metadata.redirect_chain" :key="index">
                  <code>{{ defang(String(url)) }}</code>
                </li>
              </ol>
              <p v-if="item.metadata.redirect_chain_complete !== true" class="small muted">
                {{ t('Cette chaîne peut être incomplète ; elle reflète le rapport du provider.') }}
              </p>
            </template>
            <p class="small muted">
              {{
                t(
                  'Aucune capture ni ressource distante n’est chargée ici. Ouvrez le rapport du provider pour les consulter.'
                )
              }}
            </p>
            <a
              v-if="screenshotLink(item.metadata?.screenshot_url)"
              :href="screenshotLink(item.metadata.screenshot_url)"
              target="_blank"
              rel="noopener noreferrer"
              >{{ t('Ouvrir la capture chez urlscan') }} ↗</a
            >
          </section>
          <dl v-if="item.provider === 'dkim'">
            <dt>{{ t('Vérification DKIM') }}</dt>
            <dd>{{ resultLabel(String(item.metadata?.verification || 'unavailable')) }}</dd>
            <dt>{{ t('Domaines signataires') }}</dt>
            <dd>
              {{
                Array.isArray(item.metadata?.signing_domains)
                  ? item.metadata.signing_domains.map(String).map(defang).join(', ')
                  : '—'
              }}
            </dd>
            <dt>{{ t('Preuve vérifiée (SHA-256)') }}</dt>
            <dd class="hash">{{ item.metadata?.source_sha256 || '—' }}</dd>
          </dl>
          <p>
            <a
              v-if="safeProviderLink(item.external_url)"
              :href="safeProviderLink(item.external_url)"
              target="_blank"
              rel="noopener noreferrer"
              >{{ t('Ouvrir le rapport du provider') }} ↗</a
            >
            <button
              v-if="canWrite && item.status === 'pending'"
              class="secondary"
              :disabled="busy"
              @click="poll(item.id)"
            >
              {{ t('Récupérer le résultat') }}
            </button>
          </p>
          <details v-if="Object.keys(item.metadata || {}).length">
            <summary>{{ t('Métadonnées du provider') }}</summary>
            <pre>{{ JSON.stringify(item.metadata, null, 2) }}</pre>
          </details>
        </article>
        <PaginationControls
          :total="enrichmentTotal"
          :page="enrichmentPage"
          :page_size="enrichmentPageSize"
          :pages="Math.ceil(enrichmentTotal / enrichmentPageSize)"
          :busy="busy"
          @change="(page) => run(() => loadEnrichments(page))"
        />
      </template>
    </template>
  </section>
</template>
