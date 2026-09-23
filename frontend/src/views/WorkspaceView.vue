<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'

import AccountSecurity from '@/components/AccountSecurity.vue'
import AnalysisIntake from '@/components/AnalysisIntake.vue'
import AnalystDecision from '@/components/AnalystDecision.vue'
import CampaignWorkspace from '@/components/CampaignWorkspace.vue'
import EnrichmentResults from '@/components/EnrichmentResults.vue'
import GlobalSearch from '@/components/GlobalSearch.vue'
import InvestigationContext from '@/components/InvestigationContext.vue'
import PaginationControls from '@/components/PaginationControls.vue'
import { errorMessage, RequestError } from '@/errors'
import { locale, setLocale, setLocaleUser, t } from '@/i18n'
import router from '@/router'
import { defang, emptyPage, eventMessages, type Page, pageQuery } from '@/workspace'

type Assessment = {
  level: string
  label: string
  explanation: string
  reasons: string[]
  reported_engines: string[]
  missing_engines: string[]
  scope: string
}
type User = { id: number; username: string; role: string; active: boolean }
type Case = {
  id: number
  title: string
  description: string
  status: string
  priority: string
  assignee_id: number | null
  assignee?: string
  analysis_count?: number
  notes?: Entry[]
  events?: Entry[]
}
type Entry = {
  id: number
  username: string
  body?: string
  action?: string
  detail?: string
  created_at: string
  case_id?: number
}
type EmailReport = {
  investigation?: { bodies?: { index: number; content_type: string; text: string }[] }
  eml: {
    header: { subject: string; from_: string; to: string[]; date: string }
    bodies: { content: string; content_type: string }[]
    attachments: { filename: string; size: number; mime_type: string; hash: { sha256: string } }[]
  }
  verdicts: {
    name: string
    malicious: boolean
    score: number | null
    details: { key: string; description: string }[]
  }[]
}
type Analysis = {
  id: string
  case_id: number
  filename: string
  subject: string
  status: string
  error?: string
  error_code?: string
  sha256: string
  created_at: string
  result?: Record<string, unknown>
  assessment?: Assessment
}
type IOC = {
  id: number
  kind: string
  value: string
  verdict: string
  analysis_count: number
  case_count: number
  campaigns?: { id: number; name: string }[]
}
type Dashboard = {
  cases: number
  open_cases: number
  analyses: number
  iocs: number
  failed_analyses: number
  activity: Entry[]
  pending_verdicts?: number
  active_campaigns?: number
  frequent_iocs?: IOC[]
  recent_analyses?: Analysis[]
}
type ExtensionLink = { label: string; url: string }
const extensions = ref<{
  navigation: ExtensionLink[]
  auth_links: ExtensionLink[]
  manage_users_url?: string
  manage_integrations_url?: string
}>({ navigation: [], auth_links: [] })
function validExtension(link: ExtensionLink) {
  return (
    Boolean(link) &&
    typeof link.label === 'string' &&
    typeof link.url === 'string' &&
    /^\/(?!\/)[^\\\s]*$/.test(link.url)
  )
}
async function loadExtensions() {
  try {
    const config = await api<{
      navigation?: ExtensionLink[]
      auth_links?: ExtensionLink[]
      manage_users_url?: string
      manage_integrations_url?: string
    }>('/config')
    extensions.value = {
      navigation: (config.navigation || []).filter(validExtension),
      auth_links: (config.auth_links || []).filter(validExtension),
      manage_users_url: config.manage_users_url,
      manage_integrations_url:
        config.manage_integrations_url &&
        validExtension({ label: '', url: config.manage_integrations_url })
          ? config.manage_integrations_url
          : undefined
    }
  } catch {
    /* core supports no extensions */
  }
}

const user = ref<User | null>(null),
  ready = ref(false),
  error = ref(''),
  busy = ref(false),
  uploading = ref(false)
const mfaRequired = ref(false),
  mfaCode = ref(''),
  useRecovery = ref(false)
const tab = ref('intake'),
  username = ref(''),
  password = ref(''),
  query = ref(''),
  caseStatus = ref('')
const cases = ref<Case[]>([]),
  users = ref<User[]>([]),
  analyses = ref<Analysis[]>([]),
  iocs = ref<IOC[]>([])
const dashboard = ref<Dashboard | null>(null),
  selected = ref<Case | null>(null),
  report = ref<Analysis | null>(null)
const note = ref(''),
  showCreate = ref(false),
  caseTitle = ref(''),
  caseDescription = ref(''),
  casePriority = ref('medium')
const newName = ref(''),
  newPassword = ref(''),
  newRole = ref('analyst')
const occurrences = ref<{ id: string; filename: string; case_id: number; title: string }[] | null>(
  null
)
const casePage = ref(emptyPage<Case>()),
  analysisPage = ref(emptyPage<Analysis>()),
  iocPage = ref(emptyPage<IOC>()),
  scopedAnalyses = ref(emptyPage<Analysis>()),
  eventPage = ref(emptyPage<Entry>())
const occurrencePage =
  ref(emptyPage<{ id: string; filename: string; case_id: number; title: string }>())
const selectedIoc = ref<IOC | null>(null)
const analysisStatus = ref('')
const writer = computed(() => user.value && user.value.role !== 'viewer')
const tabs = computed(() => [
  ['intake', t('Analyser un email')],
  ['dashboard', t('Vue d’ensemble')],
  ['cases', t('Dossiers')],
  ['analyses', t('Analyses')],
  ['iocs', t('Indicateurs')],
  ['campaigns', t('Campagnes')],
  ['search', t('Recherche globale')],
  ['integrations', t('Intégrations')],
  ['security', t('Mon compte')],
  ...(user.value?.role === 'admin' && !extensions.value.manage_users_url
    ? [['users', t('Comptes')]]
    : [])
])
const navIcons: Record<string, string> = {
  intake: '↥',
  dashboard: '◫',
  cases: '▣',
  analyses: '≋',
  iocs: '⌘',
  users: '◎',
  security: '⚿',
  campaigns: '◈',
  search: '⌕',
  integrations: '⤴'
}
const labels = computed<Record<string, string>>(() => ({
  open: t('Ouvert'),
  investigating: t('En investigation'),
  resolved: t('Résolu'),
  closed: t('Clos'),
  low: t('Faible'),
  medium: t('Moyenne'),
  high: t('Haute'),
  critical: t('Critique'),
  queued: t('En attente'),
  running: t('En cours'),
  completed: t('Terminée'),
  failed: t('Échec'),
  unreviewed: t('À qualifier'),
  benign: t('Bénin'),
  suspicious: t('Suspect'),
  malicious: t('Malveillant'),
  admin: t('Administrateur'),
  analyst: t('Analyste'),
  viewer: t('Lecture seule')
}))
const formatDate = (s: string) =>
  new Date(s.replace(' ', 'T') + (/(?:Z|[+-]\d{2}:\d{2})$/.test(s) ? '' : 'Z')).toLocaleString(
    locale.value === 'fr' ? 'fr-FR' : 'en-GB'
  )
async function api<T>(path: string, method = 'GET', data?: unknown): Promise<T> {
  const form = data instanceof FormData
  const response = await fetch('/api/workspace' + path, {
    method,
    credentials: 'same-origin',
    headers: {
      'X-Requested-With': 'EML-Investigation',
      ...(!form && data !== undefined ? { 'Content-Type': 'application/json' } : {})
    },
    body: data === undefined ? undefined : form ? data : JSON.stringify(data)
  })
  if (!response.ok) {
    if (response.status === 401) {
      user.value = null
      mfaRequired.value = false
    }
    const payload = await response.json().catch(() => ({}))
    throw new RequestError(payload?.detail, response.status, payload?.code)
  }
  return response.json()
}
async function act(fn: () => Promise<void>) {
  error.value = ''
  busy.value = true
  try {
    await fn()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
async function loadCases(page = 1) {
  casePage.value = await api<Page<Case>>(
    '/cases?' + pageQuery(page, { q: query.value, status: caseStatus.value })
  )
  cases.value = casePage.value.items || []
}
async function loadAnalyses(page = 1) {
  analysisPage.value = await api<Page<Analysis>>(
    '/analyses?' + pageQuery(page, { q: query.value, status: analysisStatus.value })
  )
  analyses.value = analysisPage.value.items || []
}
async function loadIocs(page = 1) {
  iocPage.value = await api<Page<IOC>>('/iocs?' + pageQuery(page, { q: query.value }))
  iocs.value = iocPage.value.items || []
}
async function loadCaseAnalyses(page = 1) {
  if (selected.value)
    scopedAnalyses.value = await api<Page<Analysis>>(
      '/analyses?' + pageQuery(page, { case_id: selected.value.id })
    )
}
async function loadCaseEvents(page = 1) {
  if (selected.value)
    eventPage.value = await api<Page<Entry>>(
      '/cases/' + selected.value.id + '/events?' + pageQuery(page)
    )
}
async function loadOccurrences(page = 1) {
  if (selectedIoc.value) {
    occurrencePage.value = await api(
      '/iocs/' + selectedIoc.value.id + '/occurrences?' + pageQuery(page)
    )
    occurrences.value = occurrencePage.value.items
  }
}
async function refresh() {
  const [d, u] = await Promise.all([api<Dashboard>('/dashboard'), api<User[]>('/users')])
  dashboard.value = d
  users.value = u
  if (tab.value === 'dashboard' || tab.value === 'cases') await loadCases(casePage.value.page)
  if (tab.value === 'analyses' || tab.value === 'intake')
    await loadAnalyses(analysisPage.value.page)
  if (tab.value === 'iocs') await loadIocs(iocPage.value.page)
  if (selected.value) {
    selected.value = await api<Case>('/cases/' + selected.value.id)
    await Promise.all([
      loadCaseAnalyses(scopedAnalyses.value.page),
      loadCaseEvents(eventPage.value.page)
    ])
  }
  if (report.value) report.value = await api<Analysis>('/analyses/' + report.value.id)
}
async function loadPreferences() {
  setLocaleUser(user.value?.id)
  try {
    const preference = await api<{ locale: string }>('/auth/preferences')
    setLocaleUser(user.value?.id, preference.locale)
  } catch {
    /* browser preference remains available */
  }
}
async function changeLanguage(event: Event) {
  setLocale((event.target as HTMLSelectElement).value)
  if (user.value)
    await act(async () => {
      await api('/auth/preferences', 'PUT', { locale: locale.value })
    })
}
async function login() {
  await act(async () => {
    const result = await api<User | { authenticated: true } | { mfa_required: true }>(
      '/auth/login',
      'POST',
      {
        username: username.value,
        password: password.value
      }
    )
    password.value = ''
    if ('mfa_required' in result) {
      mfaRequired.value = true
      mfaCode.value = ''
      useRecovery.value = false
      user.value = null
      return
    }
    user.value = 'username' in result ? result : await api<User>('/auth/me')
    mfaRequired.value = false
    await loadPreferences()
    await syncRoute()
  })
}
function toggleRecovery() {
  useRecovery.value = !useRecovery.value
  mfaCode.value = ''
  error.value = ''
}
function restartLogin() {
  mfaRequired.value = false
  mfaCode.value = ''
  error.value = ''
}
async function verifyMfa() {
  await act(async () => {
    const result = await api<User | { authenticated: true }>('/auth/mfa/verify', 'POST', {
      code: mfaCode.value
    })
    user.value = 'username' in result ? result : await api<User>('/auth/me')
    mfaCode.value = ''
    mfaRequired.value = false
    await loadPreferences()
    await syncRoute()
  })
}
async function logout() {
  await act(async () => {
    await api('/auth/logout', 'POST')
    user.value = null
    mfaRequired.value = false
    mfaCode.value = ''
    tab.value = 'intake'
    selected.value = null
    report.value = null
    cases.value = []
    analyses.value = []
    iocs.value = []
    dashboard.value = null
  })
}
function followLink(event: MouseEvent, path: string) {
  if (event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
  event.preventDefault()
  void router.push(path)
}
async function navigate(value: string) {
  await router.push(value === 'intake' ? '/' : '/' + value)
}
async function openCase(id: number) {
  await router.push('/cases/' + id)
}
function closeCase() {
  void router.push('/cases')
}
async function syncRoute() {
  if (!user.value) return
  const route = router.currentRoute.value
  const section = route.path.split('/')[1] || 'intake'
  tab.value = section
  query.value = String(route.query.q || '')
  caseStatus.value = section === 'cases' ? String(route.query.status || '') : ''
  analysisStatus.value = section === 'analyses' ? String(route.query.status || '') : ''
  selected.value = null
  report.value = null
  occurrences.value = null
  selectedIoc.value = null
  const page = Math.max(1, Number(route.query.page || 1))
  casePage.value.page = page
  analysisPage.value.page = page
  iocPage.value.page = page
  if (section === 'cases' && route.params.id) {
    selected.value = await api<Case>('/cases/' + encodeURIComponent(String(route.params.id)))
    scopedAnalyses.value = emptyPage()
    eventPage.value = emptyPage()
  }
  if (section === 'analyses' && route.params.id)
    report.value = await api<Analysis>('/analyses/' + encodeURIComponent(String(route.params.id)))
  if (section === 'iocs' && route.params.id) {
    selectedIoc.value = await api<IOC>('/iocs/' + encodeURIComponent(String(route.params.id)))
    await loadOccurrences()
  }
  await refresh()
}
async function listPage(page = 1) {
  await router.push({
    path: '/' + tab.value,
    query: {
      q: query.value,
      page,
      status:
        tab.value === 'cases'
          ? caseStatus.value
          : tab.value === 'analyses'
            ? analysisStatus.value
            : undefined
    }
  })
}
watch(
  () => router.currentRoute.value.fullPath,
  () => {
    if (ready.value && user.value) void act(syncRoute)
  }
)
async function createCase() {
  await act(async () => {
    const c = await api<Case>('/cases', 'POST', {
      title: caseTitle.value,
      description: caseDescription.value,
      priority: casePriority.value
    })
    showCreate.value = false
    caseTitle.value = ''
    caseDescription.value = ''
    await openCase(c.id)
    await refresh()
  })
}
async function saveCase() {
  await act(async () => {
    if (selected.value) {
      await api('/cases/' + selected.value.id, 'PUT', selected.value)
      await refresh()
    }
  })
}
async function addNote() {
  await act(async () => {
    await api('/cases/' + selected.value!.id + '/notes', 'POST', { body: note.value })
    note.value = ''
    await refresh()
  })
}
async function directUpload(file: File): Promise<Analysis> {
  const form = new FormData()
  form.append('file', file)
  return api<Analysis>('/analyses', 'POST', form)
}
async function afterUpload() {
  await act(refresh)
}
const reportElement = ref<HTMLElement | null>(null)
async function revealReport() {
  await nextTick()
  reportElement.value?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
}
async function upload(event: Event) {
  const input = event.target as HTMLInputElement,
    file = input.files?.[0],
    caseId = selected.value?.id
  if (!file || !caseId) return
  if (file.size > 20 * 1024 * 1024) {
    error.value = t('Le fichier dépasse 20 Mo.')
    input.value = ''
    return
  }
  uploading.value = true
  error.value = ''
  try {
    const form = new FormData()
    form.append('file', file)
    const result = await api<Analysis>('/cases/' + caseId + '/analyses', 'POST', form)
    await refresh()
    await openReport(result.id)
    if (result.status === 'failed') error.value = errorMessage(result.error, result.error_code)
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    uploading.value = false
    input.value = ''
  }
}
async function openReport(id: string) {
  await router.push('/analyses/' + encodeURIComponent(id))
  await revealReport()
}
async function retryReport() {
  if (report.value)
    await act(async () => {
      report.value = await api<Analysis>('/analyses/' + report.value!.id + '/retry', 'POST')
    })
}
async function verdict(ioc: IOC, event: Event) {
  const value = (event.target as HTMLSelectElement).value
  await act(async () => {
    await api('/iocs/' + ioc.id, 'PUT', { verdict: value })
    await refresh()
  })
}
async function addUser() {
  await act(async () => {
    await api('/users', 'POST', {
      username: newName.value,
      password: newPassword.value,
      role: newRole.value
    })
    newName.value = ''
    newPassword.value = ''
    await refresh()
  })
}
async function saveUser(u: User) {
  await act(async () => {
    await api('/users/' + u.id, 'PUT', { role: u.role, active: !!u.active })
    await refresh()
  })
}
const emailReport = computed(() => report.value?.result as unknown as EmailReport | undefined)
const selectedEvidenceAttachments = ref<number[]>([])
watch(
  () => report.value?.id,
  () => {
    selectedEvidenceAttachments.value = []
  }
)
const evidenceDownload = computed(
  () =>
    '/api/workspace/analyses/' +
    report.value?.id +
    '/evidence.zip?attachments=' +
    selectedEvidenceAttachments.value.join(',')
)
const readableBodies = computed(
  () =>
    emailReport.value?.investigation?.bodies ||
    emailReport.value?.eml.bodies.map((body, index) => ({
      index,
      content_type: body.content_type,
      text: body.content
    })) ||
    []
)
const caseAnalyses = computed(() => scopedAnalyses.value.items)
let timer: ReturnType<typeof setInterval> | undefined
onMounted(async () => {
  await loadExtensions()
  try {
    user.value = await api<User>('/auth/me')
    await loadPreferences()
    await syncRoute()
  } catch (e) {
    if (user.value) error.value = String(e)
  } finally {
    ready.value = true
  }
  timer = setInterval(async () => {
    if (!user.value || busy.value) return
    try {
      if (report.value && ['queued', 'running'].includes(report.value.status))
        report.value = await api<Analysis>('/analyses/' + report.value.id)
      if (
        selected.value &&
        scopedAnalyses.value.items.some((a) => ['queued', 'running'].includes(a.status))
      )
        await loadCaseAnalyses(scopedAnalyses.value.page)
      if (
        tab.value === 'analyses' &&
        analyses.value.some((a) => ['queued', 'running'].includes(a.status))
      )
        await loadAnalyses(analysisPage.value.page)
    } catch {
      /* next poll retries; foreground refresh displays actionable errors */
    }
  }, 3000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<template>
  <div class="phishcase">
    <div class="language-switch">
      <label
        >{{ t('Langue') }}
        <select :value="locale" :aria-label="t('Langue')" @change="changeLanguage">
          <option value="fr">Français</option>
          <option value="en">English</option>
        </select></label
      >
    </div>
    <div v-if="!ready" class="login-shell">{{ t('Chargement de PhishCase…') }}</div>
    <div v-else-if="!user" class="login-shell">
      <form class="login-card" @submit.prevent="mfaRequired ? verifyMfa() : login()">
        <div class="brand-icon">P<span>↗</span></div>
        <p class="eyebrow">{{ t('EMAIL INVESTIGATION WORKSPACE') }}</p>
        <h1>PhishCase<span>.</span></h1>
        <p class="muted">{{ t('Des emails suspects aux dossiers résolus.') }}</p>
        <template v-if="!mfaRequired">
          <label>
            {{ t('Identifiant') }}
            <input v-model="username" autocomplete="username" required autofocus
          /></label>
          <label>
            {{ t('Mot de passe') }}
            <input v-model="password" type="password" autocomplete="current-password" required
          /></label>
        </template>
        <template v-else>
          <h2>{{ t('Vérification en deux étapes') }}</h2>
          <p class="muted">
            {{
              useRecovery
                ? t('Saisissez un de vos codes de récupération. Il sera consommé après validation.')
                : t('Saisissez le code à 6 chiffres de votre application d’authentification.')
            }}
          </p>
          <label
            >{{ useRecovery ? t('Code de récupération') : t('Code de l’application')
            }}<input
              :key="String(useRecovery)"
              v-model="mfaCode"
              :inputmode="useRecovery ? 'text' : 'numeric'"
              :pattern="useRecovery ? undefined : '[0-9]{6}'"
              :maxlength="useRecovery ? 64 : 6"
              autocomplete="one-time-code"
              spellcheck="false"
              required
              autofocus
          /></label>
          <button type="button" class="text-link" @click="toggleRecovery">
            {{
              useRecovery ? t('Utiliser mon application') : t('Utiliser un code de récupération')
            }}
          </button>
        </template>
        <p v-if="error" role="alert" class="error">{{ error }}</p>
        <button class="primary" :disabled="busy">
          {{
            busy
              ? t('Connexion…')
              : mfaRequired
                ? t('Vérifier et me connecter →')
                : t('Ouvrir mon espace →')
          }}
        </button>
        <button
          v-if="mfaRequired"
          type="button"
          class="secondary"
          :disabled="busy"
          @click="restartLogin"
        >
          {{ t('Recommencer la connexion') }}
        </button>
        <p v-for="link in extensions.auth_links" :key="link.url">
          <a class="text-link" :href="link.url">{{ t(link.label) }}</a>
        </p>
        <p class="small muted">{{ t('Espace réservé à votre équipe d’investigation.') }}</p>
      </form>
    </div>
    <div v-else class="workspace">
      <aside class="sidebar">
        <a href="/" class="brand" @click.exact.prevent="navigate('intake')"
          ><span class="brand-icon">P<span>↗</span></span
          >PhishCase<span class="brand-dot">.</span></a
        >
        <p class="eyebrow">{{ t('ESPACE D’INVESTIGATION') }}</p>
        <nav>
          <button
            v-for="[id, label] in tabs"
            :key="id"
            :class="{ active: tab === id }"
            @click="navigate(id!)"
          >
            <span class="nav-symbol">{{ navIcons[id!] }}</span
            >{{ label
            }}<span v-if="id === 'cases'" class="count">{{ dashboard?.open_cases || 0 }}</span>
          </button>
          <a
            v-for="link in extensions.navigation"
            :key="link.url"
            class="extension-nav"
            :href="link.url"
            ><span class="nav-symbol">↗</span>{{ t(link.label) }}</a
          >
        </nav>
        <div class="sidebar-bottom">
          <div class="avatar">{{ user.username.slice(0, 2).toUpperCase() }}</div>
          <div>
            <strong>{{ user.username }}</strong
            ><small>{{ labels[user.role] }}</small>
          </div>
          <button :title="t('Déconnexion')" :aria-label="t('Déconnexion')" @click="logout">
            ↪
          </button>
        </div>
      </aside>
      <main>
        <header>
          <span>
            {{ t('WORKSPACE') }} <span class="slash">/</span>
            {{ tabs.find((t) => t[0] === tab)?.[1] }}</span
          >
          <div class="live"><i></i> {{ t('Équipe connectée') }}</div>
        </header>
        <div class="content">
          <div v-if="error" class="error" role="alert">
            {{ error }} <button @click="error = ''" :aria-label="t('Fermer l’erreur')">×</button>
          </div>
          <div class="page-heading">
            <div>
              <p class="eyebrow">
                {{
                  tab === 'intake'
                    ? t('UN EMAIL SUSPECT ?')
                    : tab === 'dashboard'
                      ? t('CHAQUE INDICE COMPTE')
                      : t('PHISHCASE / INVESTIGATION')
                }}
              </p>
              <h1>{{ selected ? selected.title : tabs.find((t) => t[0] === tab)?.[1] }}</h1>
              <p class="muted">
                {{
                  tab === 'intake'
                    ? t(
                        'Déposez votre email. Consultez le résultat. Retrouvez-le automatiquement dans son dossier.'
                      )
                    : tab === 'security'
                      ? t('Gérez la sécurité de votre compte et vos moyens de récupération.')
                      : tab === 'dashboard'
                        ? t('Votre activité, vos dossiers et les signaux à suivre.')
                        : selected
                          ? t('Dossier #') + selected.id + t(' · preuves, analyses et chronologie')
                          : t('Centralisez les éléments utiles à votre investigation.')
                }}
              </p>
            </div>
            <button
              v-if="tab === 'cases' && writer && !selected"
              class="primary"
              @click="showCreate = !showCreate"
            >
              {{ t('+ Nouveau dossier') }}</button
            ><button v-else class="secondary" :disabled="busy" @click="act(refresh)">
              {{ t('↻ Actualiser') }}
            </button>
          </div>
          <EnrichmentResults
            v-if="tab === 'integrations'"
            :request="api"
            :admin="user.role === 'admin'"
            :settings-url="extensions.manage_integrations_url"
          />
          <GlobalSearch v-if="tab === 'search'" :request="api" />
          <CampaignWorkspace v-if="tab === 'campaigns'" :request="api" :can-write="!!writer" />
          <AccountSecurity v-if="tab === 'security'" :request="api" />
          <AnalysisIntake
            v-show="tab === 'intake'"
            :upload-file="directUpload"
            :get-analysis="(id) => api<Analysis>('/analyses/' + id)"
            :can-upload="!!writer"
            @completed="afterUpload"
            @open="openReport"
            @case="openCase"
          />
          <section v-if="report" ref="reportElement" class="panel report">
            <div class="panel-title">
              <h2>{{ report.subject || report.filename }}</h2>
              <div>
                <a
                  class="secondary"
                  :href="'/api/workspace/analyses/' + report.id + '/export.json'"
                  download
                  >{{ t('Exporter JSON') }}</a
                >
                <a
                  class="secondary"
                  :href="'/api/workspace/analyses/' + report.id + '/export.html?locale=' + locale"
                  download
                  >{{ t('Rapport HTML') }}</a
                >
                <a class="secondary" :href="evidenceDownload" download>{{
                  t('Télécharger le paquet de preuves')
                }}</a>
                <button class="secondary" @click="navigate('analyses')">{{ t('Fermer') }}</button>
              </div>
            </div>
            <div
              v-if="report.assessment"
              class="assessment-banner"
              :data-state="report.assessment.level"
              role="status"
            >
              <h2>{{ t('Résultats automatiques') }} · {{ t(report.assessment.label) }}</h2>
              <p>{{ t(report.assessment.explanation) }}</p>
              <p v-if="report.assessment.missing_engines.length" class="small">
                {{ t('Contrôles sans résultat :') }}
                {{ report.assessment.missing_engines.join(', ') }}
              </p>
              <small>{{ t(report.assessment.scope) }}</small>
            </div>
            <a
              class="text-link"
              :href="'/cases/' + report!.case_id"
              @click="followLink($event, '/cases/' + report!.case_id)"
            >
              {{ t('Retrouver dans le dossier #') }} {{ report.case_id }} →
            </a>
            <p>
              <span class="badge" :data-state="report.status">{{ labels[report.status] }}</span>
            </p>
            <p class="small muted hash">SHA-256 · {{ report.sha256 }}</p>
            <p v-if="report.error" class="error">
              {{ errorMessage(report.error, report.error_code) }}
            </p>
            <button
              v-if="writer && report.status === 'failed'"
              class="secondary"
              :disabled="busy"
              @click="retryReport"
            >
              {{ t('Relancer l’analyse') }}
            </button>
            <p v-if="['queued', 'running'].includes(report.status)" role="status">
              {{
                t('Analyse côté serveur. Vous pouvez fermer cet onglet ; le traitement continue.')
              }}
            </p>
            <AnalystDecision :analysis-id="report.id" :request="api" :can-write="!!writer" />
            <a
              class="text-link"
              :href="'/api/workspace/analyses/' + report.id + '/source'"
              download
            >
              {{ t('Télécharger le fichier original →') }}
            </a>
            <EnrichmentResults
              v-if="report.result"
              :analysis-id="report.id"
              :result="report.result"
              :request="api"
              :can-write="!!writer"
            />
            <InvestigationContext
              v-if="report.result"
              :analysis-id="report.id"
              :result="report.result"
              :request="api"
            />
            <div v-if="emailReport" class="email-report">
              <dl>
                <dt>{{ t('Expéditeur') }}</dt>
                <dd>{{ emailReport.eml.header.from_ }}</dd>
                <dt>{{ t('Destinataires') }}</dt>
                <dd>{{ emailReport.eml.header.to.join(', ') }}</dd>
                <dt>{{ t('Date du message') }}</dt>
                <dd>{{ emailReport.eml.header.date || t('Non renseignée') }}</dd>
              </dl>
              <h2>{{ t('Résultats des moteurs') }}</h2>
              <p class="small muted" v-if="!emailReport.verdicts.length">
                {{
                  t(
                    'Aucun verdict disponible. L’absence de verdict ne signifie pas que cet email est sûr.'
                  )
                }}
              </p>
              <article v-for="(v, index) in emailReport.verdicts" :key="index" class="verdict">
                <strong>{{ v.name }}</strong>
                <span class="badge" :data-state="v.malicious ? 'malicious' : 'benign'">{{
                  v.malicious ? t('Signal suspect') : t('Aucun signal détecté')
                }}</span>
                <p v-for="(d, j) in v.details" :key="j" class="small">
                  {{ d.key }} · {{ d.description }}
                </p>
              </article>
              <h2>{{ t('Contenu de l’email') }}</h2>
              <details
                v-for="body in readableBodies"
                :key="body.index"
                :open="body.content_type === 'text/plain'"
              >
                <summary>
                  {{ body.content_type || t('Texte') }} {{ t('· partie') }} {{ body.index + 1 }}
                </summary>
                <pre>{{ body.text }}</pre>
              </details>
              <h2>{{ t('Pièces jointes ·') }} {{ emailReport.eml.attachments.length }}</h2>
              <p class="small muted">
                {{
                  t(
                    'Le paquet contient l’original et son manifeste. Cochez les pièces jointes à y ajouter ; aucune n’est incluse par défaut.'
                  )
                }}
              </p>
              <p class="small muted">
                {{ t('Conservées avec cet email dans le dossier #') }} {{ report.case_id }}
                {{ t('. Analyse statique Office ; pas d’exécution en sandbox.') }}
              </p>
              <article v-for="(a, index) in emailReport.eml.attachments" :key="index" class="note">
                <label class="security-check"
                  ><input v-model="selectedEvidenceAttachments" type="checkbox" :value="index" />{{
                    t('Inclure dans le paquet')
                  }}</label
                >
                <strong>{{ a.filename }}</strong>
                <a
                  class="text-link attachment-download"
                  :href="'/api/workspace/analyses/' + report.id + '/attachments/' + index"
                  download
                >
                  {{ t('Télécharger la pièce jointe') }}
                </a>
                <p class="small muted">{{ a.mime_type }} · {{ a.size }} {{ t('octets') }}</p>
                <p class="hash small">SHA-256 · {{ a.hash.sha256 }}</p>
              </article>
            </div>
            <details v-if="report.result">
              <summary>{{ t('Résultat complet de l’analyse') }}</summary>
              <pre>{{ JSON.stringify(report.result, null, 2) }}</pre>
            </details>
          </section>
          <template v-if="tab === 'dashboard' && dashboard">
            <div class="stats">
              <div
                v-for="[label, value, caption] in [
                  [t('Dossiers ouverts'), dashboard.open_cases, t('À investiguer')],
                  [t('Analyses'), dashboard.analyses, t('Emails traités ou en cours')],
                  [t('Indicateurs'), dashboard.iocs, t('IOC uniques extraits')],
                  [t('Échecs'), dashboard.failed_analyses, t('Analyses à vérifier')],
                  [
                    t('Verdicts en attente'),
                    dashboard.pending_verdicts ?? 0,
                    t('Décisions humaines attendues')
                  ],
                  [
                    t('Campagnes actives'),
                    dashboard.active_campaigns ?? 0,
                    t('Investigations regroupées')
                  ]
                ]"
                :key="String(label)"
                class="stat"
              >
                <p>{{ label }}</p>
                <strong>{{ value }}</strong
                ><small>{{ caption }}</small>
              </div>
            </div>
            <div class="dashboard-grid">
              <section class="panel">
                <div class="panel-title">
                  <h2>{{ t('Analyses récentes') }}</h2>
                  <button @click="navigate('analyses')">{{ t('Voir les analyses') }} →</button>
                </div>
                <p v-if="!dashboard.recent_analyses?.length" class="empty">
                  {{ t('Aucun résultat trouvé.') }}
                </p>
                <a
                  v-for="analysis in dashboard.recent_analyses || []"
                  :key="analysis.id"
                  class="case-row"
                  :href="'/analyses/' + analysis.id"
                  @click="followLink($event, '/analyses/' + analysis.id)"
                >
                  <span>{{ analysis.subject || analysis.filename }}</span
                  ><span class="badge" :data-state="analysis.status">{{
                    labels[analysis.status]
                  }}</span>
                </a>
              </section>
              <section class="panel">
                <div class="panel-title">
                  <h2>{{ t('IOC fréquents') }}</h2>
                  <button @click="navigate('campaigns')">{{ t('Campagnes actives') }} →</button>
                </div>
                <p v-if="!dashboard.frequent_iocs?.length" class="empty">
                  {{ t('Aucun résultat trouvé.') }}
                </p>
                <a
                  v-for="ioc in dashboard.frequent_iocs || []"
                  :key="ioc.id"
                  class="case-row"
                  :href="'/iocs/' + ioc.id"
                  @click="followLink($event, '/iocs/' + ioc.id)"
                >
                  <code class="ioc-value">{{ defang(ioc.value) }}</code
                  ><small
                    >{{ ioc.analysis_count }} {{ t('Analyses') }} · {{ ioc.case_count }}
                    {{ t('Dossiers') }}</small
                  >
                </a>
              </section>
              <section class="panel">
                <div class="panel-title">
                  <h2>{{ t('Dossiers récents') }}</h2>
                  <button @click="navigate('cases')">{{ t('Voir les dossiers →') }}</button>
                </div>
                <div v-if="!cases.length" class="empty">
                  {{ t('Votre première investigation commence ici.') }}
                  <button v-if="writer" class="primary" @click="navigate('intake')">
                    {{ t('Analyser un email') }}
                  </button>
                </div>
                <a
                  v-for="c in cases.slice(0, 6)"
                  :key="c.id"
                  class="case-row"
                  :href="'/cases/' + c.id"
                  @click="followLink($event, '/cases/' + c.id)"
                >
                  <span class="case-number">#{{ String(c.id).padStart(3, '0') }}</span>
                  <div>
                    <strong>{{ c.title }}</strong
                    ><small
                      >{{ c.assignee || t('Non assigné') }} · {{ c.analysis_count }}
                      {{ t('analyse(s)') }}
                    </small>
                  </div>
                  <span class="badge" :data-state="c.priority">{{ labels[c.priority] }}</span
                  ><span>↗</span>
                </a>
              </section>
              <section class="panel">
                <div class="panel-title">
                  <h2>{{ t('Journal d’activité') }}</h2>
                  <span class="muted small"> {{ t('9 derniers événements') }} </span>
                </div>
                <p v-if="!dashboard.activity.length" class="empty">
                  {{ t('Aucune activité enregistrée.') }}
                </p>
                <div v-for="e in dashboard.activity.slice(0, 9)" :key="e.id" class="timeline">
                  <i></i>
                  <div>
                    <strong>{{ t(eventMessages[e.action || ''] || e.action || '') }}</strong
                    ><small
                      >{{ e.username || t('Système') }} · {{ formatDate(e.created_at) }}</small
                    >
                  </div>
                </div>
              </section>
            </div>
          </template>
          <template v-if="tab === 'cases'">
            <form
              v-if="showCreate && !selected"
              class="panel form-grid"
              @submit.prevent="createCase"
            >
              <h2>{{ t('Nouveau dossier') }}</h2>
              <label> {{ t('Titre') }} <input v-model="caseTitle" maxlength="200" required /></label
              ><label>
                {{ t('Description') }}
                <textarea v-model="caseDescription" rows="3"></textarea></label
              ><label>
                {{ t('Priorité') }}
                <select v-model="casePriority">
                  <option v-for="p in ['low', 'medium', 'high', 'critical']" :key="p" :value="p">
                    {{ labels[p] }}
                  </option>
                </select></label
              >
              <div>
                <button class="primary" :disabled="busy">{{ t('Créer le dossier') }}</button>
                <button type="button" class="secondary" @click="showCreate = false">
                  {{ t('Annuler') }}
                </button>
              </div>
            </form>
            <template v-if="selected">
              <button class="back" @click="closeCase">{{ t('← Tous les dossiers') }}</button>
              <section class="panel form-grid">
                <label>
                  {{ t('Titre') }}
                  <input v-model="selected.title" :disabled="!writer" maxlength="200" /></label
                ><label>
                  {{ t('Description') }}
                  <textarea v-model="selected.description" :disabled="!writer" rows="3"></textarea>
                </label>
                <div class="inline-fields">
                  <label>
                    {{ t('Statut') }}
                    <select v-model="selected.status" :disabled="!writer">
                      <option
                        v-for="s in ['open', 'investigating', 'resolved', 'closed']"
                        :key="s"
                        :value="s"
                      >
                        {{ labels[s] }}
                      </option>
                    </select></label
                  ><label>
                    {{ t('Priorité') }}
                    <select v-model="selected.priority" :disabled="!writer">
                      <option
                        v-for="s in ['low', 'medium', 'high', 'critical']"
                        :key="s"
                        :value="s"
                      >
                        {{ labels[s] }}
                      </option>
                    </select></label
                  ><label>
                    {{ t('Responsable') }}
                    <select v-model="selected.assignee_id" :disabled="!writer">
                      <option :value="null">{{ t('Non assigné') }}</option>
                      <option
                        v-for="u in users.filter((u) => u.active && u.role !== 'viewer')"
                        :key="u.id"
                        :value="u.id"
                      >
                        {{ u.username }}
                      </option>
                    </select></label
                  >
                </div>
                <div v-if="writer">
                  <button class="primary" :disabled="busy" @click="saveCase">
                    {{ t('Enregistrer') }}
                  </button>
                </div>
              </section>
              <section class="panel">
                <div class="panel-title">
                  <h2>{{ t('Analyses du dossier') }}</h2>
                  <label v-if="writer" class="upload-button"
                    >{{ uploading ? t('Envoi en cours…') : '+ ' + t('Analyser un email')
                    }}<input type="file" accept=".eml,.msg" :disabled="uploading" @change="upload"
                  /></label>
                </div>
                <p class="small muted">
                  {{
                    t(
                      'EML / MSG · 20 Mo maximum · Le résultat et les IOC sont conservés dans le dossier.'
                    )
                  }}
                </p>
                <p v-if="!caseAnalyses.length" class="empty">
                  {{ t('Aucun email analysé pour ce dossier.') }}
                </p>
                <a
                  v-for="a in caseAnalyses"
                  :key="a.id"
                  class="case-row"
                  :href="'/analyses/' + a.id"
                  @click="followLink($event, '/analyses/' + a.id)"
                >
                  <div>
                    <strong>{{ a.subject || a.filename }}</strong
                    ><small>{{ a.filename }} · {{ formatDate(a.created_at) }}</small>
                  </div>
                  <span class="badge" :data-state="a.status">{{ labels[a.status] }}</span
                  ><span>↗</span></a
                ><PaginationControls
                  v-bind="scopedAnalyses"
                  :busy="busy"
                  @change="(p) => act(() => loadCaseAnalyses(p))"
                />
              </section>
              <div class="dashboard-grid">
                <section class="panel">
                  <h2>{{ t('Notes d’investigation') }}</h2>
                  <form v-if="writer" @submit.prevent="addNote">
                    <label>
                      {{ t('Nouvelle note') }}
                      <textarea
                        v-model="note"
                        rows="3"
                        required
                        maxlength="20000"
                      ></textarea></label
                    ><button class="primary" :disabled="busy">{{ t('Ajouter la note') }}</button>
                  </form>
                  <article v-for="n in selected.notes" :key="n.id" class="note">
                    <small>{{ n.username }} · {{ formatDate(n.created_at) }}</small>
                    <p>{{ n.body }}</p>
                  </article>
                  <p v-if="!selected.notes?.length" class="muted small">
                    {{ t('Aucune note pour le moment.') }}
                  </p>
                </section>
                <section class="panel">
                  <h2>{{ t('Chronologie') }}</h2>
                  <div v-for="e in eventPage.items" :key="e.id" class="timeline">
                    <i></i>
                    <div>
                      <strong>{{ t(eventMessages[e.action || ''] || e.action || '') }}</strong
                      ><small>{{ e.username }} · {{ formatDate(e.created_at) }}</small>
                    </div>
                  </div>
                  <PaginationControls
                    v-bind="eventPage"
                    :busy="busy"
                    @change="(p) => act(() => loadCaseEvents(p))"
                  />
                </section>
              </div>
            </template>
            <template v-else
              ><form class="filters" @submit.prevent="listPage(1)">
                <input
                  v-model="query"
                  :aria-label="t('Rechercher un dossier')"
                  :placeholder="t('Rechercher un dossier…')"
                /><select
                  v-model="caseStatus"
                  :aria-label="t('Filtrer par statut')"
                  @change="listPage(1)"
                >
                  <option value="">{{ t('Tous les statuts') }}</option>
                  <option
                    v-for="s in ['open', 'investigating', 'resolved', 'closed']"
                    :value="s"
                    :key="s"
                  >
                    {{ labels[s] }}
                  </option></select
                ><button class="secondary">{{ t('Rechercher') }}</button>
              </form>
              <div class="panel table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>{{ t('Dossier') }}</th>
                      <th>{{ t('Statut') }}</th>
                      <th>{{ t('Priorité') }}</th>
                      <th>{{ t('Responsable') }}</th>
                      <th>{{ t('Analyses') }}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="c in cases" :key="c.id">
                      <td>
                        <a
                          class="text-link"
                          :href="'/cases/' + c.id"
                          @click="followLink($event, '/cases/' + c.id)"
                        >
                          <small>#{{ c.id }}</small> {{ c.title }}
                        </a>
                      </td>
                      <td>
                        <span class="badge" :data-state="c.status">{{ labels[c.status] }}</span>
                      </td>
                      <td>
                        <span class="badge" :data-state="c.priority">{{ labels[c.priority] }}</span>
                      </td>
                      <td>{{ c.assignee || t('Non assigné') }}</td>
                      <td>{{ c.analysis_count }}</td>
                    </tr>
                  </tbody>
                </table>
                <p v-if="!cases.length" class="empty">{{ t('Aucun dossier trouvé.') }}</p>
                <PaginationControls v-bind="casePage" :busy="busy" @change="listPage" /></div
            ></template>
          </template>
          <section v-if="tab === 'analyses' && !report" class="panel table-wrap">
            <form class="filters" @submit.prevent="listPage(1)">
              <input
                v-model="query"
                :placeholder="t('Rechercher une analyse')"
                :aria-label="t('Rechercher une analyse')"
              /><select
                v-model="analysisStatus"
                :aria-label="t('Filtrer par statut')"
                @change="listPage(1)"
              >
                <option value="">{{ t('Tous les statuts') }}</option>
                <option
                  v-for="state in ['queued', 'running', 'completed', 'failed']"
                  :key="state"
                  :value="state"
                >
                  {{ labels[state] }}
                </option></select
              ><button class="secondary">{{ t('Rechercher') }}</button>
            </form>
            <table>
              <thead>
                <tr>
                  <th>{{ t('Email') }}</th>
                  <th>{{ t('Dossier') }}</th>
                  <th>{{ t('État') }}</th>
                  <th>{{ t('Date') }}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="a in analyses" :key="a.id">
                  <td>
                    <strong>{{ a.subject || a.filename }}</strong
                    ><small class="block">{{ a.filename }}</small>
                  </td>
                  <td>
                    <a
                      class="text-link"
                      :href="'/cases/' + a.case_id"
                      @click="followLink($event, '/cases/' + a.case_id)"
                      >#{{ a.case_id }}</a
                    >
                  </td>
                  <td>
                    <span class="badge" :data-state="a.status">{{ labels[a.status] }}</span>
                  </td>
                  <td>{{ formatDate(a.created_at) }}</td>
                  <td>
                    <a
                      class="text-link"
                      :href="'/analyses/' + a.id"
                      @click="followLink($event, '/analyses/' + a.id)"
                      >{{ t('Ouvrir →') }}</a
                    >
                  </td>
                </tr>
              </tbody>
            </table>
            <p v-if="!analyses.length" class="empty">
              {{
                t(
                  'Déposez un email dans « Analyser un email » : son dossier sera créé automatiquement.'
                )
              }}
            </p>
            <PaginationControls v-bind="analysisPage" :busy="busy" @change="listPage" />
          </section>
          <template v-if="tab === 'iocs'"
            ><form class="filters" @submit.prevent="listPage(1)">
              <input
                v-model="query"
                :aria-label="t('Rechercher un IOC')"
                :placeholder="t('Domaine, URL, IP, email, empreinte…')"
              /><button class="secondary">{{ t('Rechercher') }}</button>
            </form>
            <section class="panel table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{{ t('Type') }}</th>
                    <th>{{ t('Indicateur') }}</th>
                    <th>{{ t('Qualification') }}</th>
                    <th>{{ t('Présence') }}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="i in iocs" :key="i.id">
                    <td>
                      <span class="badge">{{ i.kind }}</span>
                    </td>
                    <td class="ioc-value">{{ defang(i.value) }}</td>
                    <td>
                      <select
                        :value="i.verdict"
                        :disabled="!writer || busy"
                        :aria-label="t('Qualification de l’IOC')"
                        @change="verdict(i, $event)"
                      >
                        <option
                          v-for="v in ['unreviewed', 'benign', 'suspicious', 'malicious']"
                          :key="v"
                          :value="v"
                        >
                          {{ labels[v] }}
                        </option>
                      </select>
                    </td>
                    <td>
                      <a
                        class="text-link"
                        :href="'/iocs/' + i.id"
                        @click="followLink($event, '/iocs/' + i.id)"
                      >
                        {{ i.case_count }} {{ t('dossier(s) ·') }} {{ i.analysis_count }}
                        {{ t('analyse(s)') }}
                      </a>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-if="!iocs.length" class="empty">
                {{ t('Les indicateurs apparaîtront après l’analyse de vos emails.') }}
              </p>
              <PaginationControls v-bind="iocPage" :busy="busy" @change="listPage" />
            </section>
            <section v-if="occurrences" class="panel">
              <div class="panel-title">
                <h2>
                  {{ selectedIoc ? defang(selectedIoc.value) : t('Présence de l’indicateur') }}
                </h2>
                <button @click="navigate('iocs')">{{ t('Fermer') }}</button>
              </div>
              <p v-if="selectedIoc?.campaigns?.length">
                {{ t('Campagnes') }}:
                <a
                  v-for="campaign in selectedIoc.campaigns"
                  :key="campaign.id"
                  :href="'/campaigns/' + campaign.id"
                  @click="followLink($event, '/campaigns/' + campaign.id)"
                  >{{ campaign.name }}
                </a>
              </p>
              <div v-for="o in occurrences" :key="o.id" class="case-row">
                <a
                  class="text-link"
                  :href="'/cases/' + o.case_id"
                  @click="followLink($event, '/cases/' + o.case_id)"
                >
                  #{{ o.case_id }} · {{ o.title }}</a
                ><a
                  class="text-link"
                  :href="'/analyses/' + o.id"
                  @click="followLink($event, '/analyses/' + o.id)"
                  >{{ o.filename }} →</a
                >
              </div>
              <PaginationControls
                v-bind="occurrencePage"
                :busy="busy"
                @change="(p) => act(() => loadOccurrences(p))"
              /></section
          ></template>
          <template v-if="tab === 'users' && user.role === 'admin'"
            ><form class="panel form-grid" @submit.prevent="addUser">
              <h2>{{ t('Inviter un membre de l’équipe') }}</h2>
              <div class="inline-fields">
                <label>
                  {{ t('Identifiant') }}
                  <input
                    v-model="newName"
                    required
                    maxlength="80"
                    pattern="[a-zA-Z0-9_.@\-]+" /></label
                ><label>
                  {{ t('Mot de passe initial') }}
                  <input
                    v-model="newPassword"
                    type="password"
                    required
                    minlength="12"
                    maxlength="256"
                    autocomplete="new-password" /></label
                ><label>
                  {{ t('Rôle') }}
                  <select v-model="newRole">
                    <option v-for="r in ['analyst', 'viewer', 'admin']" :key="r" :value="r">
                      {{ labels[r] }}
                    </option>
                  </select></label
                >
              </div>
              <div>
                <button class="primary" :disabled="busy">{{ t('Créer le compte') }}</button>
              </div>
            </form>
            <section class="panel table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{{ t('Compte') }}</th>
                    <th>{{ t('Rôle') }}</th>
                    <th>{{ t('Actif') }}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="u in users" :key="u.id">
                    <td>{{ u.username }}</td>
                    <td>
                      <select
                        v-model="u.role"
                        :disabled="u.id === user.id"
                        :aria-label="t('Rôle du compte')"
                      >
                        <option v-for="r in ['admin', 'analyst', 'viewer']" :key="r" :value="r">
                          {{ labels[r] }}
                        </option>
                      </select>
                    </td>
                    <td>
                      <input
                        type="checkbox"
                        v-model="u.active"
                        :disabled="u.id === user.id"
                        :aria-label="t('Compte actif')"
                      />
                    </td>
                    <td>
                      <button
                        class="secondary"
                        :disabled="busy || u.id === user.id"
                        @click="saveUser(u)"
                      >
                        {{ t('Enregistrer') }}
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </section></template
          >
          <footer>{{ t('PhishCase · Investigation email · Basé sur eml_analyzer') }}</footer>
        </div>
      </main>
    </div>
  </div>
</template>

<style>
@import url('../workspace.css');
</style>
