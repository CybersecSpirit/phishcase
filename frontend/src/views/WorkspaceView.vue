<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'

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
  sha256: string
  created_at: string
  result?: Record<string, unknown>
}
type IOC = {
  id: number
  kind: string
  value: string
  verdict: string
  analysis_count: number
  case_count: number
}
type Dashboard = {
  cases: number
  open_cases: number
  analyses: number
  iocs: number
  failed_analyses: number
  activity: Entry[]
}
const user = ref<User | null>(null),
  ready = ref(false),
  error = ref(''),
  busy = ref(false),
  uploading = ref(false)
const tab = ref('dashboard'),
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
const writer = computed(() => user.value && user.value.role !== 'viewer')
const tabs = computed(() => [
  ['dashboard', 'Vue d’ensemble'],
  ['cases', 'Dossiers'],
  ['analyses', 'Analyses'],
  ['iocs', 'Indicateurs'],
  ...(user.value?.role === 'admin' ? [['users', 'Comptes']] : [])
])
const navIcons: Record<string, string> = {
  dashboard: '◫',
  cases: '▣',
  analyses: '≋',
  iocs: '⌘',
  users: '◎'
}
const labels: Record<string, string> = {
  open: 'Ouvert',
  investigating: 'En investigation',
  resolved: 'Résolu',
  closed: 'Clos',
  low: 'Faible',
  medium: 'Moyenne',
  high: 'Haute',
  critical: 'Critique',
  queued: 'En attente',
  running: 'En cours',
  completed: 'Terminée',
  failed: 'Échec',
  unreviewed: 'À qualifier',
  benign: 'Bénin',
  suspicious: 'Suspect',
  malicious: 'Malveillant',
  admin: 'Administrateur',
  analyst: 'Analyste',
  viewer: 'Lecture seule'
}
const formatDate = (s: string) =>
  new Date(s.replace(' ', 'T') + (s.endsWith('Z') ? '' : 'Z')).toLocaleString('fr-FR')
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
    if (response.status === 401) user.value = null
    const payload = await response.json().catch(() => ({}))
    throw new Error(
      typeof payload.detail === 'string' ? payload.detail : `Requête refusée (${response.status})`
    )
  }
  return response.json()
}
async function act(fn: () => Promise<void>) {
  error.value = ''
  busy.value = true
  try {
    await fn()
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Erreur inattendue'
  } finally {
    busy.value = false
  }
}
async function refresh() {
  const [d, c, a, i, u] = await Promise.all([
    api<Dashboard>('/dashboard'),
    api<Case[]>('/cases?q=' + encodeURIComponent(query.value) + '&status=' + caseStatus.value),
    api<Analysis[]>('/analyses'),
    api<IOC[]>('/iocs?q=' + encodeURIComponent(query.value)),
    api<User[]>('/users')
  ])
  dashboard.value = d
  cases.value = c
  analyses.value = a
  iocs.value = i
  users.value = u
  if (selected.value) selected.value = await api<Case>('/cases/' + selected.value.id)
}
async function login() {
  await act(async () => {
    user.value = await api<User>('/auth/login', 'POST', {
      username: username.value,
      password: password.value
    })
    password.value = ''
    await refresh()
  })
}
async function logout() {
  await act(async () => {
    await api('/auth/logout', 'POST')
    user.value = null
    selected.value = null
    report.value = null
    cases.value = []
    analyses.value = []
    iocs.value = []
    dashboard.value = null
  })
}
async function navigate(value: string) {
  tab.value = value
  selected.value = null
  report.value = null
  occurrences.value = null
  query.value = ''
  await act(refresh)
}
async function openCase(id: number) {
  await act(async () => {
    selected.value = await api<Case>('/cases/' + id)
    tab.value = 'cases'
    report.value = null
  })
}
async function startCase() {
  await navigate('cases')
  showCreate.value = true
}
function closeCase() {
  selected.value = null
  report.value = null
}
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
    selected.value = c
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
async function upload(event: Event) {
  const input = event.target as HTMLInputElement,
    file = input.files?.[0],
    caseId = selected.value?.id
  if (!file || !caseId) return
  if (file.size > 20 * 1024 * 1024) {
    error.value = 'Le fichier dépasse 20 Mo.'
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
    report.value = result
    if (result.status === 'failed') error.value = result.error || 'Analyse échouée'
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Échec de l’envoi'
  } finally {
    uploading.value = false
    input.value = ''
  }
}
async function openReport(id: string) {
  await act(async () => {
    report.value = await api<Analysis>('/analyses/' + id)
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
async function showOccurrences(id: number) {
  await act(async () => {
    occurrences.value = await api('/iocs/' + id + '/occurrences')
  })
}
function exportReport() {
  if (!report.value) return
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(report.value, null, 2)], { type: 'application/json' })
  )
  const a = document.createElement('a')
  a.href = url
  a.download = 'phishcase-' + report.value.id + '.json'
  a.click()
  URL.revokeObjectURL(url)
}
const emailReport = computed(() => report.value?.result as unknown as EmailReport | undefined)
const caseAnalyses = computed(() => analyses.value.filter((a) => a.case_id === selected.value?.id))
let timer: ReturnType<typeof setInterval> | undefined
onMounted(async () => {
  try {
    user.value = await api<User>('/auth/me')
    await refresh()
  } catch (e) {
    if (user.value) error.value = String(e)
  } finally {
    ready.value = true
  }
  timer = setInterval(() => {
    if (user.value && !busy.value)
      api<Analysis[]>('/analyses')
        .then((a) => (analyses.value = a))
        .catch(() => {})
  }, 5000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<template>
  <div class="phishcase">
    <div v-if="!ready" class="login-shell">Chargement de PhishCase…</div>
    <div v-else-if="!user" class="login-shell">
      <form class="login-card" @submit.prevent="login">
        <div class="brand-icon">P<span>↗</span></div>
        <p class="eyebrow">EMAIL INVESTIGATION WORKSPACE</p>
        <h1>PhishCase<span>.</span></h1>
        <p class="muted">Des emails suspects aux dossiers résolus.</p>
        <label
          >Identifiant<input v-model="username" autocomplete="username" required autofocus
        /></label>
        <label
          >Mot de passe<input
            v-model="password"
            type="password"
            autocomplete="current-password"
            required
        /></label>
        <p v-if="error" role="alert" class="error">{{ error }}</p>
        <button class="primary" :disabled="busy">
          {{ busy ? 'Connexion…' : 'Ouvrir mon espace →' }}
        </button>
        <p class="small muted">Espace réservé à votre équipe d’investigation.</p>
      </form>
    </div>
    <div v-else class="workspace">
      <aside class="sidebar">
        <a href="#" class="brand" @click.prevent="navigate('dashboard')"
          ><span class="brand-icon">P<span>↗</span></span
          >PhishCase<span class="brand-dot">.</span></a
        >
        <p class="eyebrow">ESPACE D’INVESTIGATION</p>
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
        </nav>
        <div class="sidebar-bottom">
          <div class="avatar">{{ user.username.slice(0, 2).toUpperCase() }}</div>
          <div>
            <strong>{{ user.username }}</strong
            ><small>{{ labels[user.role] }}</small>
          </div>
          <button title="Déconnexion" aria-label="Déconnexion" @click="logout">↪</button>
        </div>
      </aside>
      <main>
        <header>
          <span
            >WORKSPACE <span class="slash">/</span> {{ tabs.find((t) => t[0] === tab)?.[1] }}</span
          >
          <div class="live"><i></i> Équipe connectée</div>
        </header>
        <div class="content">
          <div v-if="error" class="error" role="alert">
            {{ error }} <button @click="error = ''" aria-label="Fermer l’erreur">×</button>
          </div>
          <div class="page-heading">
            <div>
              <p class="eyebrow">
                {{ tab === 'dashboard' ? 'CHAQUE INDICE COMPTE' : 'PHISHCASE / INVESTIGATION' }}
              </p>
              <h1>{{ selected ? selected.title : tabs.find((t) => t[0] === tab)?.[1] }}</h1>
              <p class="muted">
                {{
                  tab === 'dashboard'
                    ? 'Votre activité, vos dossiers et les signaux à suivre.'
                    : selected
                      ? 'Dossier #' + selected.id + ' · preuves, analyses et chronologie'
                      : 'Centralisez les éléments utiles à votre investigation.'
                }}
              </p>
            </div>
            <button
              v-if="tab === 'cases' && writer && !selected"
              class="primary"
              @click="showCreate = !showCreate"
            >
              + Nouveau dossier</button
            ><button v-else class="secondary" :disabled="busy" @click="act(refresh)">
              ↻ Actualiser
            </button>
          </div>
          <template v-if="tab === 'dashboard' && dashboard">
            <div class="stats">
              <div
                v-for="[label, value, caption] in [
                  ['Dossiers ouverts', dashboard.open_cases, 'À investiguer'],
                  ['Analyses', dashboard.analyses, 'Emails traités ou en cours'],
                  ['Indicateurs', dashboard.iocs, 'IOC uniques extraits'],
                  ['Échecs', dashboard.failed_analyses, 'Analyses à vérifier']
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
                  <h2>Dossiers récents</h2>
                  <button @click="navigate('cases')">Voir les dossiers →</button>
                </div>
                <div v-if="!cases.length" class="empty">
                  Votre première investigation commence ici.<button
                    v-if="writer"
                    class="primary"
                    @click="startCase"
                  >
                    Créer un dossier
                  </button>
                </div>
                <button
                  v-for="c in cases.slice(0, 6)"
                  :key="c.id"
                  class="case-row"
                  @click="openCase(c.id)"
                >
                  <span class="case-number">#{{ String(c.id).padStart(3, '0') }}</span>
                  <div>
                    <strong>{{ c.title }}</strong
                    ><small
                      >{{ c.assignee || 'Non assigné' }} · {{ c.analysis_count }} analyse(s)</small
                    >
                  </div>
                  <span class="badge" :data-state="c.priority">{{ labels[c.priority] }}</span
                  ><span>↗</span>
                </button>
              </section>
              <section class="panel">
                <div class="panel-title">
                  <h2>Journal d’activité</h2>
                  <span class="muted small">30 derniers événements</span>
                </div>
                <p v-if="!dashboard.activity.length" class="empty">Aucune activité enregistrée.</p>
                <div v-for="e in dashboard.activity.slice(0, 9)" :key="e.id" class="timeline">
                  <i></i>
                  <div>
                    <strong>{{ e.action }}</strong
                    ><small>{{ e.username || 'Système' }} · {{ formatDate(e.created_at) }}</small>
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
              <h2>Nouveau dossier</h2>
              <label>Titre<input v-model="caseTitle" maxlength="200" required /></label
              ><label>Description<textarea v-model="caseDescription" rows="3"></textarea></label
              ><label
                >Priorité<select v-model="casePriority">
                  <option v-for="p in ['low', 'medium', 'high', 'critical']" :key="p" :value="p">
                    {{ labels[p] }}
                  </option>
                </select></label
              >
              <div>
                <button class="primary" :disabled="busy">Créer le dossier</button>
                <button type="button" class="secondary" @click="showCreate = false">Annuler</button>
              </div>
            </form>
            <template v-if="selected">
              <button class="back" @click="closeCase">← Tous les dossiers</button>
              <section class="panel form-grid">
                <label
                  >Titre<input
                    v-model="selected.title"
                    :disabled="!writer"
                    maxlength="200" /></label
                ><label
                  >Description<textarea
                    v-model="selected.description"
                    :disabled="!writer"
                    rows="3"
                  ></textarea>
                </label>
                <div class="inline-fields">
                  <label
                    >Statut<select v-model="selected.status" :disabled="!writer">
                      <option
                        v-for="s in ['open', 'investigating', 'resolved', 'closed']"
                        :key="s"
                        :value="s"
                      >
                        {{ labels[s] }}
                      </option>
                    </select></label
                  ><label
                    >Priorité<select v-model="selected.priority" :disabled="!writer">
                      <option
                        v-for="s in ['low', 'medium', 'high', 'critical']"
                        :key="s"
                        :value="s"
                      >
                        {{ labels[s] }}
                      </option>
                    </select></label
                  ><label
                    >Responsable<select v-model="selected.assignee_id" :disabled="!writer">
                      <option :value="null">Non assigné</option>
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
                  <button class="primary" :disabled="busy" @click="saveCase">Enregistrer</button>
                </div>
              </section>
              <section class="panel">
                <div class="panel-title">
                  <h2>Analyses du dossier</h2>
                  <label v-if="writer" class="upload-button"
                    >{{ uploading ? 'Analyse en cours…' : '+ Analyser un email'
                    }}<input type="file" accept=".eml,.msg" :disabled="uploading" @change="upload"
                  /></label>
                </div>
                <p class="small muted">
                  EML / MSG · 20 Mo maximum · Le résultat et les IOC sont conservés dans le dossier.
                </p>
                <p v-if="!caseAnalyses.length" class="empty">
                  Aucun email analysé pour ce dossier.
                </p>
                <button
                  v-for="a in caseAnalyses"
                  :key="a.id"
                  class="case-row"
                  @click="openReport(a.id)"
                >
                  <div>
                    <strong>{{ a.subject || a.filename }}</strong
                    ><small>{{ a.filename }} · {{ formatDate(a.created_at) }}</small>
                  </div>
                  <span class="badge" :data-state="a.status">{{ labels[a.status] }}</span
                  ><span>↗</span>
                </button>
              </section>
              <div class="dashboard-grid">
                <section class="panel">
                  <h2>Notes d’investigation</h2>
                  <form v-if="writer" @submit.prevent="addNote">
                    <label
                      >Nouvelle note<textarea
                        v-model="note"
                        rows="3"
                        required
                        maxlength="20000"
                      ></textarea></label
                    ><button class="primary" :disabled="busy">Ajouter la note</button>
                  </form>
                  <article v-for="n in selected.notes" :key="n.id" class="note">
                    <small>{{ n.username }} · {{ formatDate(n.created_at) }}</small>
                    <p>{{ n.body }}</p>
                  </article>
                  <p v-if="!selected.notes?.length" class="muted small">
                    Aucune note pour le moment.
                  </p>
                </section>
                <section class="panel">
                  <h2>Chronologie</h2>
                  <div v-for="e in selected.events" :key="e.id" class="timeline">
                    <i></i>
                    <div>
                      <strong>{{ e.action }}</strong
                      ><small>{{ e.username }} · {{ formatDate(e.created_at) }}</small>
                    </div>
                  </div>
                </section>
              </div>
            </template>
            <template v-else
              ><form class="filters" @submit.prevent="act(refresh)">
                <input
                  v-model="query"
                  aria-label="Rechercher un dossier"
                  placeholder="Rechercher un dossier…"
                /><select
                  v-model="caseStatus"
                  aria-label="Filtrer par statut"
                  @change="act(refresh)"
                >
                  <option value="">Tous les statuts</option>
                  <option
                    v-for="s in ['open', 'investigating', 'resolved', 'closed']"
                    :value="s"
                    :key="s"
                  >
                    {{ labels[s] }}
                  </option></select
                ><button class="secondary">Rechercher</button>
              </form>
              <div class="panel table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Dossier</th>
                      <th>Statut</th>
                      <th>Priorité</th>
                      <th>Responsable</th>
                      <th>Analyses</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="c in cases" :key="c.id">
                      <td>
                        <button class="text-link" @click="openCase(c.id)">
                          <small>#{{ c.id }}</small> {{ c.title }}
                        </button>
                      </td>
                      <td>
                        <span class="badge" :data-state="c.status">{{ labels[c.status] }}</span>
                      </td>
                      <td>
                        <span class="badge" :data-state="c.priority">{{ labels[c.priority] }}</span>
                      </td>
                      <td>{{ c.assignee || 'Non assigné' }}</td>
                      <td>{{ c.analysis_count }}</td>
                    </tr>
                  </tbody>
                </table>
                <p v-if="!cases.length" class="empty">Aucun dossier trouvé.</p>
              </div></template
            >
          </template>
          <section v-if="tab === 'analyses'" class="panel table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Dossier</th>
                  <th>État</th>
                  <th>Date</th>
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
                    <button class="text-link" @click="openCase(a.case_id)">#{{ a.case_id }}</button>
                  </td>
                  <td>
                    <span class="badge" :data-state="a.status">{{ labels[a.status] }}</span>
                  </td>
                  <td>{{ formatDate(a.created_at) }}</td>
                  <td><button class="text-link" @click="openReport(a.id)">Ouvrir →</button></td>
                </tr>
              </tbody>
            </table>
            <p v-if="!analyses.length" class="empty">
              Créez un dossier et importez un email pour lancer une analyse.
            </p>
          </section>
          <template v-if="tab === 'iocs'"
            ><form class="filters" @submit.prevent="act(refresh)">
              <input
                v-model="query"
                aria-label="Rechercher un IOC"
                placeholder="Domaine, URL, IP, email, empreinte…"
              /><button class="secondary">Rechercher</button>
            </form>
            <section class="panel table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Indicateur</th>
                    <th>Qualification</th>
                    <th>Présence</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="i in iocs" :key="i.id">
                    <td>
                      <span class="badge">{{ i.kind }}</span>
                    </td>
                    <td class="ioc-value">{{ i.value }}</td>
                    <td>
                      <select
                        :value="i.verdict"
                        :disabled="!writer || busy"
                        aria-label="Qualification de l’IOC"
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
                      <button class="text-link" @click="showOccurrences(i.id)">
                        {{ i.case_count }} dossier(s) · {{ i.analysis_count }} analyse(s)
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-if="!iocs.length" class="empty">
                Les indicateurs apparaîtront après l’analyse de vos emails.
              </p>
            </section>
            <section v-if="occurrences" class="panel">
              <div class="panel-title">
                <h2>Présence de l’indicateur</h2>
                <button @click="occurrences = null">Fermer</button>
              </div>
              <div v-for="o in occurrences" :key="o.id" class="case-row">
                <button class="text-link" @click="openCase(o.case_id)">
                  #{{ o.case_id }} · {{ o.title }}</button
                ><button class="text-link" @click="openReport(o.id)">{{ o.filename }} →</button>
              </div>
            </section></template
          >
          <template v-if="tab === 'users' && user.role === 'admin'"
            ><form class="panel form-grid" @submit.prevent="addUser">
              <h2>Inviter un membre de l’équipe</h2>
              <div class="inline-fields">
                <label
                  >Identifiant<input
                    v-model="newName"
                    required
                    maxlength="80"
                    pattern="[a-zA-Z0-9_.@\-]+" /></label
                ><label
                  >Mot de passe initial<input
                    v-model="newPassword"
                    type="password"
                    required
                    minlength="12"
                    maxlength="256"
                    autocomplete="new-password" /></label
                ><label
                  >Rôle<select v-model="newRole">
                    <option v-for="r in ['analyst', 'viewer', 'admin']" :key="r" :value="r">
                      {{ labels[r] }}
                    </option>
                  </select></label
                >
              </div>
              <div><button class="primary" :disabled="busy">Créer le compte</button></div>
            </form>
            <section class="panel table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Compte</th>
                    <th>Rôle</th>
                    <th>Actif</th>
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
                        aria-label="Rôle du compte"
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
                        aria-label="Compte actif"
                      />
                    </td>
                    <td>
                      <button
                        class="secondary"
                        :disabled="busy || u.id === user.id"
                        @click="saveUser(u)"
                      >
                        Enregistrer
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </section></template
          >
          <section v-if="report" class="panel report">
            <div class="panel-title">
              <h2>{{ report.subject || report.filename }}</h2>
              <div>
                <button class="secondary" @click="exportReport">Exporter JSON</button>
                <button class="secondary" @click="report = null">Fermer</button>
              </div>
            </div>
            <p>
              <span class="badge" :data-state="report.status">{{ labels[report.status] }}</span>
            </p>
            <p class="small muted hash">SHA-256 · {{ report.sha256 }}</p>
            <p v-if="report.error" class="error">{{ report.error }}</p>
            <a class="text-link" :href="'/api/workspace/analyses/' + report.id + '/source'" download
              >Télécharger le fichier original →</a
            >
            <div v-if="emailReport" class="email-report">
              <dl>
                <dt>Expéditeur</dt>
                <dd>{{ emailReport.eml.header.from_ }}</dd>
                <dt>Destinataires</dt>
                <dd>{{ emailReport.eml.header.to.join(', ') }}</dd>
                <dt>Date du message</dt>
                <dd>{{ emailReport.eml.header.date || 'Non renseignée' }}</dd>
              </dl>
              <h2>Résultats des moteurs</h2>
              <p class="small muted" v-if="!emailReport.verdicts.length">
                Aucun verdict disponible. L’absence de verdict ne signifie pas que cet email est
                sûr.
              </p>
              <article v-for="(v, index) in emailReport.verdicts" :key="index" class="verdict">
                <strong>{{ v.name }}</strong>
                <span class="badge" :data-state="v.malicious ? 'malicious' : 'benign'">{{
                  v.malicious ? 'Signal suspect' : 'Aucun signal détecté'
                }}</span>
                <p v-for="(d, j) in v.details" :key="j" class="small">
                  {{ d.key }} · {{ d.description }}
                </p>
              </article>
              <h2>Contenu de l’email</h2>
              <details
                v-for="(body, index) in emailReport.eml.bodies"
                :key="index"
                :open="body.content_type === 'text/plain'"
              >
                <summary>{{ body.content_type || 'Texte' }} · partie {{ index + 1 }}</summary>
                <pre>{{ body.content }}</pre>
              </details>
              <h2>Pièces jointes · {{ emailReport.eml.attachments.length }}</h2>
              <article v-for="(a, index) in emailReport.eml.attachments" :key="index" class="note">
                <strong>{{ a.filename }}</strong>
                <p class="small muted">{{ a.mime_type }} · {{ a.size }} octets</p>
                <p class="hash small">SHA-256 · {{ a.hash.sha256 }}</p>
              </article>
            </div>
            <details v-if="report.result">
              <summary>Résultat complet de l’analyse</summary>
              <pre>{{ JSON.stringify(report.result, null, 2) }}</pre>
            </details>
          </section>
          <footer>PhishCase · Investigation email · Basé sur eml_analyzer</footer>
        </div>
      </main>
    </div>
  </div>
</template>

<style>
@import url('../workspace.css');
</style>
