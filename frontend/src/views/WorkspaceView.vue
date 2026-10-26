<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'

import AccountSecurity from '@/components/AccountSecurity.vue'
import ActionMenu from '@/components/ActionMenu.vue'
import AnalysisIntake from '@/components/AnalysisIntake.vue'
import AnalystDecision from '@/components/AnalystDecision.vue'
import CampaignWorkspace from '@/components/CampaignWorkspace.vue'
import EmailCampaignPicker from '@/components/EmailCampaignPicker.vue'
import EnrichmentResults from '@/components/EnrichmentResults.vue'
import GlobalSearch from '@/components/GlobalSearch.vue'
import IntelligenceWorkspace from '@/components/IntelligenceWorkspace.vue'
import InvestigationContext from '@/components/InvestigationContext.vue'
import OperationalFollowup from '@/components/OperationalFollowup.vue'
import PaginationControls from '@/components/PaginationControls.vue'
import TaskGuide from '@/components/TaskGuide.vue'
import { errorMessage, RequestError } from '@/errors'
import { locale, setLocale, setLocaleUser, t } from '@/i18n'
import { vResponsiveTable } from '@/responsiveTable'
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
  case_id: number | null
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
  campaign_count: number
  campaigns?: { id: number; name: string }[]
}
type Dashboard = {
  analyses: number
  iocs: number
  failed_analyses: number
  activity: Entry[]
  pending_verdicts?: number
  active_campaigns?: number
  frequent_iocs?: IOC[]
  recent_analyses?: Analysis[]
  analyses_to_review?: Analysis[]
  campaigns_to_follow?: {
    id: number
    name: string
    assignee?: string
    priority: string
    analysis_count: number
  }[]
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
  busy = ref(false)
const mfaRequired = ref(false),
  mfaCode = ref(''),
  useRecovery = ref(false)
const mobileMenuOpen = ref(false)
const mobileMenuButton = ref<HTMLButtonElement | null>(null)
function closeMobileMenu() {
  if (mobileMenuOpen.value) {
    mobileMenuOpen.value = false
    void nextTick(() => mobileMenuButton.value?.focus())
  }
}
const tab = ref('intake'),
  username = ref(''),
  password = ref(''),
  query = ref('')
const users = ref<User[]>([]),
  analyses = ref<Analysis[]>([]),
  iocs = ref<IOC[]>([])
const dashboard = ref<Dashboard | null>(null),
  report = ref<Analysis | null>(null)
const newName = ref(''),
  newPassword = ref(''),
  newRole = ref('analyst')
const occurrences = ref<{ id: string; filename: string; case_id: number; title: string }[] | null>(
  null
)
type FollowupAction = {
  id: number
  case_id: number | null
  campaign_id: number | null
  analysis_id: string | null
  title: string
  owner: string
  due_date: string
  status: string
}
const selectedEmailIds = ref<string[]>([])
const reportCampaigns = ref<{ id: number; name: string }[]>([])
const actionScope = ref('mine'),
  actionPage = ref(emptyPage<FollowupAction>())
const actionRows = computed(() => actionPage.value.items)
const reportView = ref('message')
const actionNames: Record<string, string> = {
  todo: 'À faire',
  doing: 'En cours',
  done: 'Terminée',
  cancelled: 'Annulée'
}
const analysisPage = ref(emptyPage<Analysis>()),
  iocPage = ref(emptyPage<IOC>())
const occurrencePage =
  ref(emptyPage<{ id: string; filename: string; case_id: number; title: string }>())
const selectedIoc = ref<IOC | null>(null)
const analysisStatus = ref('')
const writer = computed(() => user.value && user.value.role !== 'viewer')
const tabs = computed(() => [
  ['intake', t('Réception')],
  ['dashboard', t('Vue d’ensemble')],
  ['analyses', t('Emails')],
  ['iocs', t('IoC')],
  ['campaigns', t('Campagnes')],
  ['intelligence', t('Renseignement')],
  ['actions', t('Actions')],
  ['search', t('Recherche globale')],
  ['integrations', t('Intégrations')],
  ['security', t('Mon compte')],
  ...(user.value?.role === 'admin' && !extensions.value.manage_users_url
    ? [['users', t('Comptes')]]
    : [])
])
const primaryTabs = computed(() =>
  tabs.value.filter(([id]) => ['intake', 'analyses', 'iocs', 'campaigns', 'actions'].includes(id!))
)
const explorerTabs = computed(() =>
  tabs.value.filter(([id]) => ['dashboard', 'analyses', 'search', 'intelligence'].includes(id!))
)
const accountTabs = computed(() =>
  tabs.value.filter(([id]) => ['integrations', 'security', 'users'].includes(id!))
)
const navIcons: Record<string, string> = {
  intake: '↥',
  dashboard: '◫',
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
function changeActionScope(value: string) {
  actionScope.value = value
  void act(refresh)
}
async function loadActionPage(page = 1) {
  actionPage.value = await api<Page<FollowupAction>>(
    '/actions?scope=' + actionScope.value + '&page=' + page
  )
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
  if (tab.value === 'actions') await loadActionPage()
  if (tab.value === 'analyses' || tab.value === 'intake')
    await loadAnalyses(analysisPage.value.page)
  if (tab.value === 'iocs') await loadIocs(iocPage.value.page)
  if (report.value) {
    report.value = await api<Analysis>('/analyses/' + report.value.id)
    reportCampaigns.value = await api('/analyses/' + report.value.id + '/campaigns')
  }
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
    selectedEmailIds.value = []
    report.value = null
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
  closeMobileMenu()
  await router.push(value === 'intake' ? '/' : '/' + value)
}
async function syncRoute() {
  if (!user.value) return
  if (router.currentRoute.value.path.startsWith('/cases')) {
    const id = router.currentRoute.value.params.id
    const target = id ? (await api<{ url: string }>('/legacy/cases/' + id)).url : '/campaigns'
    await router.replace(target)
    return syncRoute()
  }
  if (!user.value) return
  const route = router.currentRoute.value
  const section = route.path.split('/')[1] || 'intake'
  tab.value = section
  query.value = String(route.query.q || '')
  analysisStatus.value = section === 'analyses' ? String(route.query.status || '') : ''
  selectedEmailIds.value = []
  report.value = null
  reportView.value = 'message'
  occurrences.value = null
  selectedIoc.value = null
  const page = Math.max(1, Number(route.query.page || 1))
  analysisPage.value.page = page
  iocPage.value.page = page
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
      status: tab.value === 'analyses' ? analysisStatus.value : undefined
    }
  })
}
watch(
  () => router.currentRoute.value.fullPath,
  () => {
    if (ready.value && user.value) void act(syncRoute)
  }
)
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
  <div class="phishcase folio-shell">
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
    <div v-else-if="!user" class="login-shell folio-auth">
      <section class="folio-auth-brand">
        <p class="folio-brand"><img class="brand-symbol" :src="'/phishcase-mark.svg?v=20261026-mails'" alt="" width="42" height="42" />PhishCase</p>
        <p class="folio-meta">INVESTIGATION / EMAIL</p>
        <h1>{{ t('Chaque message mérite une lecture attentive.') }}</h1>
        <p>
          {{
            t(
              'Du premier signalement à la décision argumentée. Votre espace d’investigation et votre équipe.'
            )
          }}
        </p>
      </section>
      <form
        class="login-card folio-auth-form"
        @submit.prevent="mfaRequired ? verifyMfa() : login()"
      >
        <p class="folio-reference">PHISHCASE / {{ t('Identification') }}</p>
        <p class="eyebrow">{{ t('EMAIL INVESTIGATION WORKSPACE') }}</p>
        <h1>{{ t('Ouvrir votre espace') }}</h1>
        <p class="muted">{{ t('Des emails suspects aux investigations résolues.') }}</p>
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
      <aside class="sidebar folio-mast" @keydown.esc="closeMobileMenu">
        <div class="sidebar-heading">
          <a href="/" class="brand" @click.exact.prevent="navigate('intake')"
            ><img class="brand-symbol" :src="'/phishcase-mark.svg?v=20261026-mails'" alt="" width="36" height="36" />PhishCase<span class="brand-dot"
              >.</span
            ></a
          >
          <button
            ref="mobileMenuButton"
            class="mobile-menu-button"
            type="button"
            aria-controls="workspace-navigation"
            :aria-expanded="mobileMenuOpen"
            @click="mobileMenuOpen = !mobileMenuOpen"
          >
            {{ mobileMenuOpen ? t('Fermer le menu') : t('Menu') }}
          </button>
        </div>
        <div
          id="workspace-navigation"
          class="sidebar-navigation"
          :class="{ 'is-open': mobileMenuOpen }"
        >
          <p class="eyebrow">{{ t('ESPACE D’INVESTIGATION') }}</p>
          <nav>
            <button
              v-for="[id, label] in primaryTabs"
              :key="id"
              :class="{ active: tab === id }"
              :aria-current="tab === id ? 'page' : undefined"
              @click="navigate(id!)"
            >
              <span class="nav-symbol">{{ navIcons[id!] }}</span
              >{{ label }}
            </button>
            <ActionMenu
              label="Explorer"
              class="nav-explorer"
              :class="{ active: explorerTabs.some(([id]) => id === tab) }"
              ><button
                v-for="[id, label] in explorerTabs"
                :key="id"
                class="menu-item"
                @click="navigate(id!)"
              >
                {{ label }}
              </button></ActionMenu
            >
          </nav>
          <div class="sidebar-bottom">
            <div class="avatar">{{ user.username.slice(0, 2).toUpperCase() }}</div>
            <div>
              <strong>{{ user.username }}</strong
              ><small>{{ labels[user.role] }}</small>
            </div>
            <ActionMenu label="Profil" class="profile-menu"
              ><button
                v-for="[id, label] in accountTabs"
                :key="id"
                class="menu-item"
                @click="navigate(id!)"
              >
                {{ label }}</button
              ><a
                v-for="link in extensions.navigation"
                :key="link.url"
                class="menu-item"
                :href="link.url"
                >{{ t(link.label) }}</a
              ><button class="menu-item" @click="logout">{{ t('Déconnexion') }}</button></ActionMenu
            >
          </div>
        </div>
      </aside>
      <main class="folio-main">
        <header>
          <span>
            {{ t('WORKSPACE') }} <span class="slash">/</span>
            {{ tabs.find((t) => t[0] === tab)?.[1] }}</span
          >
          <div class="folio-reference">{{ user.username }} / {{ labels[user.role] }}</div>
        </header>
        <div class="content">
          <div v-if="error" class="error" role="alert">
            {{ error }} <button @click="error = ''" :aria-label="t('Fermer l’erreur')">×</button>
          </div>
          <div class="page-heading folio-heading">
            <div>
              <p class="eyebrow">
                {{
                  tab === 'intake'
                    ? t('UN EMAIL SUSPECT ?')
                    : tab === 'dashboard'
                      ? t('CHAQUE IoC COMPTE')
                      : t('PHISHCASE / INVESTIGATION')
                }}
              </p>
              <h1>{{ tabs.find((t) => t[0] === tab)?.[1] }}</h1>
              <p class="muted">
                {{
                  tab === 'intake'
                    ? t(
                        'Déposez votre email. Consultez son analyse. Regroupez les messages utiles dans une campagne si nécessaire.'
                      )
                    : tab === 'security'
                      ? t('Gérez la sécurité de votre compte et vos moyens de récupération.')
                      : tab === 'dashboard'
                        ? t('Vos emails, les analyses à vérifier et les campagnes à suivre.')
                        : t('Centralisez les éléments utiles à votre investigation.')
                }}
              </p>
            </div>
            <button class="quiet-button" :disabled="busy" @click="act(refresh)">
              {{ t('↻ Actualiser') }}
            </button>
          </div>
          <TaskGuide :task="report ? 'decision' : tab" />
          <IntelligenceWorkspace
            v-if="tab === 'intelligence'"
            :request="api"
            :can-write="!!writer"
          />
          <section v-if="tab === 'actions'" class="panel">
            <div class="folio-tabs">
              <button
                :class="{ active: actionScope === 'mine' }"
                @click="changeActionScope('mine')"
              >
                {{ t('Mes actions') }}</button
              ><button
                :class="{ active: actionScope === 'team' }"
                @click="changeActionScope('team')"
              >
                {{ t('Équipe') }}
              </button>
            </div>
            <table v-responsive-table>
              <thead>
                <tr>
                  <th>{{ t('Action') }}</th>
                  <th>{{ t('Campagne ou email') }}</th>
                  <th>{{ t('Responsable') }}</th>
                  <th>{{ t('Échéance') }}</th>
                  <th>{{ t('Statut') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in actionRows" :key="item.id">
                  <td>
                    <a
                      :href="
                        item.campaign_id
                          ? '/campaigns/' + item.campaign_id
                          : '/analyses/' + item.analysis_id
                      "
                      @click="
                        followLink(
                          $event,
                          item.campaign_id
                            ? '/campaigns/' + item.campaign_id
                            : '/analyses/' + item.analysis_id
                        )
                      "
                      >{{ item.title }}</a
                    >
                  </td>
                  <td>{{ item.campaign_id ? '#' + item.campaign_id : t('Email') }}</td>
                  <td>{{ item.owner || t('Non assigné') }}</td>
                  <td>{{ item.due_date || '—' }}</td>
                  <td>
                    <span class="badge">{{ t(actionNames[item.status] || item.status) }}</span>
                  </td>
                </tr>
              </tbody>
            </table>
            <p v-if="!actionRows.length" class="empty">{{ t('Aucune action à suivre.') }}</p>
            <PaginationControls
              v-bind="actionPage"
              :busy="busy"
              @change="(p) => act(() => loadActionPage(p))"
            />
          </section>
          <EnrichmentResults
            v-if="tab === 'integrations'"
            :request="api"
            :admin="user.role === 'admin'"
            :settings-url="extensions.manage_integrations_url"
          />
          <GlobalSearch v-if="tab === 'search'" :request="api" />
          <CampaignWorkspace
            v-if="tab === 'campaigns'"
            :request="api"
            :can-write="!!writer"
            :users="users"
          />
          <AccountSecurity v-if="tab === 'security'" :request="api" />
          <AnalysisIntake
            v-show="tab === 'intake'"
            :upload-file="directUpload"
            :get-analysis="(id) => api<Analysis>('/analyses/' + id)"
            :can-upload="!!writer"
            @completed="afterUpload"
            @open="openReport"
          />
          <div v-if="tab === 'intake'" class="reception-ledger">
            <section class="panel">
              <div class="panel-title">
                <h2>{{ t('Messages reçus') }}</h2>
                <button class="text-link" @click="navigate('analyses')">
                  {{ t('Toutes les analyses') }} →
                </button>
              </div>
              <p v-if="!analyses.length" class="empty">
                {{ t('Déposez votre premier message pour commencer.') }}
              </p>
              <a
                v-for="a in analyses.slice(0, 8)"
                :key="a.id"
                :href="'/analyses/' + a.id"
                class="case-row"
                @click="followLink($event, '/analyses/' + a.id)"
                ><div>
                  <strong>{{ a.subject || a.filename }}</strong
                  ><small>{{ a.filename }} · {{ formatDate(a.created_at) }}</small>
                </div>
                <span class="badge" :data-state="a.status">{{ labels[a.status] }}</span
                ><span>↗</span></a
              >
            </section>
            <section class="panel reception-note">
              <h2>{{ t('Campagnes à suivre') }}</h2>
              <p class="small muted">
                {{ t('Le suivi collectif des emails liés, par priorité et responsable.') }}
              </p>
              <a
                v-for="c in dashboard?.campaigns_to_follow || []"
                :key="c.id"
                class="case-row"
                :href="'/campaigns/' + c.id"
                @click="followLink($event, '/campaigns/' + c.id)"
                ><div>
                  <strong>{{ c.name }}</strong
                  ><small
                    >{{ c.assignee || t('Non assigné') }} · {{ c.analysis_count }}
                    {{ t('Emails') }}</small
                  >
                </div>
                <span class="badge" :data-state="c.priority">{{ labels[c.priority] }}</span></a
              >
              <p v-if="!dashboard?.campaigns_to_follow?.length" class="empty">
                {{ t('Aucune campagne à suivre.') }}
              </p>
              <button class="text-link" @click="navigate('campaigns')">
                {{ t('Toutes les campagnes') }} →
              </button>
            </section>
            <section class="panel">
              <h2>{{ t('Analyses à vérifier') }}</h2>
              <a
                v-for="a in dashboard?.analyses_to_review || []"
                :key="a.id"
                class="case-row"
                :href="'/analyses/' + a.id"
                @click="followLink($event, '/analyses/' + a.id)"
                ><strong>{{ a.subject || a.filename }}</strong
                ><span class="badge" :data-state="a.status">{{ labels[a.status] }}</span></a
              >
              <p v-if="!dashboard?.analyses_to_review?.length" class="empty">
                {{ t('Aucune analyse à vérifier.') }}
              </p>
            </section>
            <section class="panel">
              <h2>{{ t('IoC fréquents') }}</h2>
              <a
                v-for="i in dashboard?.frequent_iocs || []"
                :key="i.id"
                class="case-row"
                :href="'/iocs/' + i.id"
                @click="followLink($event, '/iocs/' + i.id)"
                ><code>{{ defang(i.value) }}</code
                ><small>{{ i.analysis_count }} {{ t('Emails') }}</small></a
              >
              <p v-if="!dashboard?.frequent_iocs?.length" class="empty">
                {{ t('Aucun IoC extrait.') }}
              </p>
            </section>
          </div>
          <section v-if="report" ref="reportElement" class="panel report">
            <div class="panel-title">
              <h2>{{ report.subject || report.filename }}</h2>
              <ActionMenu>
                <a
                  class="menu-item"
                  :href="'/api/workspace/analyses/' + report.id + '/export.json'"
                  download
                  >{{ t('Exporter JSON') }}</a
                >
                <a
                  class="menu-item"
                  :href="'/api/workspace/analyses/' + report.id + '/export.html?locale=' + locale"
                  download
                  >{{ t('Rapport HTML') }}</a
                >
                <a class="menu-item" :href="evidenceDownload" download>{{
                  t('Télécharger le paquet de preuves')
                }}</a>
                <button class="menu-item" @click="navigate('analyses')">{{ t('Fermer') }}</button>
              </ActionMenu>
            </div>
            <EmailCampaignPicker :analysis-ids="[report.id]" :request="api" :can-write="!!writer" />
            <p v-for="c in reportCampaigns" :key="c.id">
              <a :href="'/campaigns/' + c.id" @click="followLink($event, '/campaigns/' + c.id)">{{
                c.name
              }}</a>
            </p>
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
            <a
              class="text-link"
              :href="'/api/workspace/analyses/' + report.id + '/source'"
              download
            >
              {{ t('Télécharger le fichier original →') }}
            </a>
            <nav class="folio-tabs" aria-label="Lecture du message">
              <button
                v-for="[id, label] in [
                  ['message', 'Message'],
                  ['indices', 'IoC et corrélations'],
                  ['technique', 'Enrichissements et technique'],
                  ['followup', 'Réponse et actions']
                ]"
                :key="id"
                :class="{ active: reportView === id }"
                @click="reportView = id!"
              >
                {{ t(label!) }}
              </button>
            </nav>
            <EnrichmentResults
              v-if="report.result && reportView === 'technique'"
              :analysis-id="report.id"
              :result="report.result"
              :request="api"
              :can-write="!!writer"
            />
            <InvestigationContext
              v-if="report.result && reportView === 'indices'"
              :analysis-id="report.id"
              :result="report.result"
              :request="api"
            />
            <div
              v-if="reportView !== 'followup'"
              class="report-columns"
              :class="{ 'decision-only': reportView !== 'message' }"
            >
              <div
                v-if="emailReport && reportView === 'message'"
                class="email-report neutralized-message"
              >
                <p class="folio-reference">01 / {{ t('Message neutralisé') }}</p>
                <dl>
                  <dt>{{ t('Expéditeur') }}</dt>
                  <dd>{{ emailReport.eml.header.from_ }}</dd>
                  <dt>{{ t('Destinataires') }}</dt>
                  <dd>{{ emailReport.eml.header.to.join(', ') }}</dd>
                  <dt>{{ t('Date du message') }}</dt>
                  <dd>{{ emailReport.eml.header.date || t('Non renseignée') }}</dd>
                </dl>
                <h2>{{ t('Contenu de l’email') }}</h2>
                <details
                  v-for="body in readableBodies"
                  :key="body.index"
                  :open="body.index === 0 || body.content_type === 'text/plain'"
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
                  {{ t('Conservées avec cet email') }}
                  {{ t('. Analyse statique Office ; pas d’exécution en sandbox.') }}
                </p>
                <article
                  v-for="(a, index) in emailReport.eml.attachments"
                  :key="index"
                  class="note"
                >
                  <label class="security-check"
                    ><input
                      v-model="selectedEvidenceAttachments"
                      type="checkbox"
                      :value="index"
                    />{{ t('Inclure dans le paquet') }}</label
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
              <aside class="decision-column">
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
                <AnalystDecision :analysis-id="report.id" :request="api" :can-write="!!writer" />
              </aside>
            </div>
            <OperationalFollowup
              v-if="reportView === 'followup'"
              :analysis-id="report.id"
              :request="api"
              :can-write="!!writer"
              :users="users"
            />
            <section v-if="emailReport && reportView === 'technique'" class="panel">
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
            </section>
            <details v-if="report.result && reportView === 'technique'">
              <summary>{{ t('Résultat complet de l’analyse') }}</summary>
              <pre>{{ JSON.stringify(report.result, null, 2) }}</pre>
            </details>
          </section>
          <template v-if="tab === 'dashboard' && dashboard">
            <div class="stats">
              <div
                v-for="[label, value, caption] in [
                  [t('Analyses'), dashboard.analyses, t('Emails traités ou en cours')],
                  [t('IoC'), dashboard.iocs, t('IoC uniques extraits')],
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
                  <h2>{{ t('IoC fréquents') }}</h2>
                  <button @click="navigate('iocs')">{{ t('Tous les IoC') }} →</button>
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
                  ><small>{{ ioc.analysis_count }} {{ t('Emails') }}</small>
                </a>
              </section>
              <section class="panel">
                <h2>{{ t('Campagnes à suivre') }}</h2>
                <a
                  v-for="c in dashboard.campaigns_to_follow || []"
                  :key="c.id"
                  class="case-row"
                  :href="'/campaigns/' + c.id"
                  @click="followLink($event, '/campaigns/' + c.id)"
                  >{{ c.name }} · {{ c.assignee || t('Non assigné') }}</a
                >
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
            <table v-responsive-table>
              <thead>
                <tr>
                  <th>{{ t('Email') }}</th>
                  <th>{{ t('Sélection') }}</th>
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
                    <input
                      v-if="writer"
                      v-model="selectedEmailIds"
                      type="checkbox"
                      :value="a.id"
                      :aria-label="t('Sélectionner cet email')"
                    />
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
              {{ t('Déposez un email : il sera conservé et analysé directement.') }}
            </p>
            <EmailCampaignPicker
              :analysis-ids="selectedEmailIds"
              :request="api"
              :can-write="!!writer"
            /><PaginationControls v-bind="analysisPage" :busy="busy" @change="listPage" />
          </section>
          <template v-if="tab === 'iocs'"
            ><form class="filters" @submit.prevent="listPage(1)">
              <input
                v-model="query"
                :aria-label="t('Rechercher un IoC')"
                :placeholder="t('Domaine, URL, IP, email, empreinte…')"
              /><button class="secondary">{{ t('Rechercher') }}</button>
            </form>
            <section class="panel table-wrap">
              <table v-responsive-table>
                <thead>
                  <tr>
                    <th>{{ t('Type') }}</th>
                    <th>{{ t('IoC') }}</th>
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
                        :aria-label="t('Qualification de l’IoC')"
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
                        {{ i.analysis_count }}
                        {{ t('analyse(s)') }}
                      </a>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-if="!iocs.length" class="empty">
                {{ t('Les IoC apparaîtront après l’analyse de vos emails.') }}
              </p>
              <PaginationControls v-bind="iocPage" :busy="busy" @change="listPage" />
            </section>
            <section v-if="occurrences" class="panel">
              <div class="panel-title">
                <h2>
                  {{ selectedIoc ? defang(selectedIoc.value) : t('Présence de l’IoC') }}
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
                  :href="'/analyses/' + o.id"
                  @click="followLink($event, '/analyses/' + o.id)"
                >
                  {{ o.filename }}</a
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
              <table v-responsive-table>
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
@import url('../design/folio.css');
@import url('../folio-workspace.css');
</style>
