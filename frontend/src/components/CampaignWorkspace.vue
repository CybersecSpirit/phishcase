<script setup lang="ts">
import { ref, watch } from 'vue'

import { errorMessage } from '@/errors'
import { t } from '@/i18n'
import router from '@/router'
import { defang, emptyPage, eventMessages, type Page, pageQuery, type Request } from '@/workspace'

import IntelligenceWorkspace from './IntelligenceWorkspace.vue'
import OperationalFollowup from './OperationalFollowup.vue'
import PaginationControls from './PaginationControls.vue'
type User = { id: number; username: string; role: string; active: boolean }
type Campaign = {
  id: number
  name: string
  description: string
  tags: string[]
  status: string
  priority: string
  assignee_id: number | null
  assignee?: string
  revision: number
  verdict: string | null
  analysis_count: number
  pending_actions: number
}
type Email = { id: string; filename: string; subject: string; status: string; created_at: string }
type IOC = { id: number; kind: string; value: string; analysis_count: number }
type Entry = { id: number; username: string; body?: string; action?: string; created_at: string }
const props = defineProps<{ request: Request; canWrite: boolean; users?: User[] }>()
const campaigns = ref(emptyPage<Campaign>()),
  selected = ref<Campaign | null>(null),
  emails = ref(emptyPage<Email>()),
  candidates = ref(emptyPage<Email>()),
  iocs = ref(emptyPage<IOC>()),
  events = ref(emptyPage<Entry>()),
  notes = ref<Entry[]>([])
const query = ref(''),
  scope = ref('mine'),
  status = ref(''),
  tag = ref(''),
  candidateQuery = ref(''),
  checked = ref<string[]>([]),
  note = ref(''),
  showCreate = ref(false),
  name = ref(''),
  tags = ref(''),
  section = ref('emails'),
  error = ref(''),
  busy = ref(false)
const names: Record<string, string> = {
  active: 'Active',
  investigating: 'En investigation',
  resolved: 'Résolu',
  closed: 'Clos',
  low: 'Basse',
  medium: 'Moyenne',
  high: 'Haute',
  critical: 'Critique',
  queued: 'En attente',
  running: 'En cours',
  completed: 'Terminée',
  failed: 'Échec'
}
async function run(fn: () => Promise<unknown>) {
  busy.value = true
  error.value = ''
  try {
    await fn()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
async function list(page = 1) {
  campaigns.value = await props.request(
    '/campaigns?' +
      pageQuery(page, { q: query.value, scope: scope.value, status: status.value, tag: tag.value })
  )
}
async function search(page = 1) {
  await router.push({
    path: '/campaigns',
    query: { q: query.value, scope: scope.value, status: status.value, tag: tag.value, page }
  })
}
async function archive() {
  await run(async () => {
    await props.request(
      '/campaigns/' + selected.value!.id + '?revision=' + selected.value!.revision,
      'DELETE'
    )
    await router.push('/campaigns')
  })
}
async function loadEmails(page = 1) {
  emails.value = await props.request(
    '/campaigns/' + selected.value!.id + '/emails?' + pageQuery(page)
  )
}
async function loadCandidates(page = 1) {
  candidates.value = await props.request(
    '/analyses?' + pageQuery(page, { q: candidateQuery.value })
  )
}
async function details(id: number) {
  selected.value = await props.request('/campaigns/' + id)
  tags.value = selected.value!.tags.join(', ')
  await Promise.all([loadEmails(), loadCandidates(), loadRecords()])
}
async function loadRecords() {
  const base = '/campaigns/' + selected.value!.id
  ;[notes.value, events.value, iocs.value] = await Promise.all([
    props.request<Entry[]>(base + '/notes'),
    props.request<Page<Entry>>(base + '/events?page=1'),
    props.request<Page<IOC>>(base + '/iocs?page=1')
  ])
}
async function create() {
  await run(async () => {
    const result = await props.request<Campaign>('/campaigns', 'POST', {
      name: name.value,
      analysis_ids: checked.value
    })
    checked.value = []
    showCreate.value = false
    name.value = ''
    await router.push('/campaigns/' + result.id)
  })
}
async function save() {
  await run(async () => {
    await props.request('/campaigns/' + selected.value!.id, 'PUT', {
      ...selected.value,
      tags: tags.value
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean)
    })
    await details(selected.value!.id)
  })
}
async function attach() {
  await run(async () => {
    await props.request('/campaigns/' + selected.value!.id + '/emails', 'POST', {
      analysis_ids: checked.value,
      revision: selected.value!.revision
    })
    checked.value = []
    await details(selected.value!.id)
  })
}
async function detach(id: string) {
  await run(async () => {
    await props.request(
      '/campaigns/' +
        selected.value!.id +
        '/emails/' +
        id +
        '?revision=' +
        selected.value!.revision,
      'DELETE'
    )
    await details(selected.value!.id)
  })
}
async function addNote() {
  await run(async () => {
    await props.request('/campaigns/' + selected.value!.id + '/notes', 'POST', { body: note.value })
    note.value = ''
    await loadRecords()
  })
}
watch(
  () => router.currentRoute.value.fullPath,
  () => {
    const route = router.currentRoute.value
    if (!route.path.startsWith('/campaigns')) return
    selected.value = null
    checked.value = []
    section.value = 'emails'
    query.value = String(route.query.q || '')
    scope.value = String(route.query.scope || 'mine')
    status.value = String(route.query.status || '')
    tag.value = String(route.query.tag || '')
    void run(async () => {
      if (route.params.id) await details(Number(route.params.id))
      else await list(Math.max(1, Number(route.query.page || 1)))
    })
  },
  { immediate: true }
)
</script>
<template>
  <section class="campaign-workspace">
    <p v-if="error" class="error" role="alert">
      {{ error }}
      <button class="secondary" @click="run(() => (selected ? details(selected.id) : list()))">
        {{ t('Actualiser') }}
      </button>
    </p>
    <template v-if="selected">
      <a href="/campaigns" class="back" @click.exact.prevent="router.push('/campaigns')"
        >← {{ t('Toutes les campagnes') }}</a
      >
      <section class="panel form-grid">
        <h2>{{ t('Campagne') }} #{{ selected.id }}</h2>
        <label
          >{{ t('Nom')
          }}<input v-model="selected.name" required maxlength="200" :disabled="!canWrite"
        /></label>
        <label
          >{{ t('Description')
          }}<textarea v-model="selected.description" rows="3" :disabled="!canWrite" />
        </label>
        <div class="inline-fields">
          <label
            >{{ t('Statut')
            }}<select v-model="selected.status" :disabled="!canWrite">
              <option
                v-for="state in ['active', 'investigating', 'resolved', 'closed']"
                :key="state"
                :value="state"
              >
                {{ t(names[state] || state) }}
              </option>
            </select></label
          >
          <label
            >{{ t('Priorité')
            }}<select v-model="selected.priority" :disabled="!canWrite">
              <option
                v-for="state in ['low', 'medium', 'high', 'critical']"
                :key="state"
                :value="state"
              >
                {{ t(names[state] || state) }}
              </option>
            </select></label
          >
          <label
            >{{ t('Responsable')
            }}<select v-model="selected.assignee_id" :disabled="!canWrite">
              <option :value="null">{{ t('Non assigné') }}</option>
              <option
                v-for="u in (users || []).filter((u) => u.active && u.role !== 'viewer')"
                :key="u.id"
                :value="u.id"
              >
                {{ u.username }}
              </option>
            </select></label
          >
        </div>
        <label>{{ t('Tags') }}<input v-model="tags" :disabled="!canWrite" /></label>
        <label
          >{{ t('Synthèse de campagne')
          }}<select v-model="selected.verdict" :disabled="!canWrite">
            <option :value="null">{{ t('Sans verdict') }}</option>
            <option
              v-for="[value, label] in [
                ['legitimate', 'Légitime'],
                ['spam', 'Spam'],
                ['phishing', 'Phishing'],
                ['credential_phishing', 'Vol d’identifiants'],
                ['malware_delivery', 'Livraison de malware'],
                ['bec_fraud', 'Fraude BEC'],
                ['suspicious', 'Suspect'],
                ['inconclusive', 'Non concluant']
              ]"
              :key="value"
              :value="value"
            >
              {{ t(label!) }}
            </option></select
          ><small>{{ t('Chaque email conserve son verdict individuel.') }}</small></label
        >
        <div class="inline-fields">
          <button v-if="canWrite" class="primary" :disabled="busy" @click="save">
            {{ t('Enregistrer') }}</button
          ><button v-if="canWrite" class="quiet-button" :disabled="busy" @click="archive">
            {{ t('Archiver la campagne') }}
          </button>
        </div>
      </section>
      <div class="folio-tabs">
        <button
          v-for="[id, label] in [
            ['emails', 'Emails'],
            ['followup', 'Réponse et actions'],
            ['intelligence', 'Renseignement documenté'],
            ['journal', 'Notes et chronologie'],
            ['iocs', 'IoC']
          ]"
          :key="id"
          :class="{ active: section === id }"
          @click="section = id!"
        >
          {{ t(label!) }}
        </button>
      </div>
      <section v-if="section === 'emails'" class="panel">
        <h2>{{ t('Emails de la campagne') }} ({{ emails.total }})</h2>
        <p class="small muted">
          {{ t('Détacher un email conserve son original, son analyse et son verdict.') }}
        </p>
        <div v-for="email in emails.items" :key="email.id" class="case-row">
          <a
            :href="'/analyses/' + email.id"
            @click.exact.prevent="router.push('/analyses/' + email.id)"
            >{{ email.subject || email.filename }}</a
          >
          <span class="badge" :data-state="email.status">{{
            t(names[email.status] || email.status)
          }}</span>
          <button
            v-if="canWrite && selected.status !== 'closed'"
            class="text-link"
            :disabled="busy"
            @click="detach(email.id)"
          >
            {{ t('Détacher') }}
          </button>
        </div>
        <p v-if="!emails.total" class="empty">{{ t('Aucun email rattaché.') }}</p>
        <PaginationControls
          v-bind="emails"
          :busy="busy"
          @change="(p) => run(() => loadEmails(p))"
        />
        <template v-if="canWrite && selected.status !== 'closed'">
          <h2>{{ t('Rattacher des emails') }}</h2>
          <form class="filters" @submit.prevent="run(() => loadCandidates())">
            <input
              v-model="candidateQuery"
              :aria-label="t('Rechercher un email')"
              :placeholder="t('Rechercher un email')"
            /><button class="secondary">{{ t('Rechercher') }}</button>
          </form>
          <label v-for="email in candidates.items" :key="email.id" class="case-row"
            ><input v-model="checked" type="checkbox" :value="email.id" />{{
              email.subject || email.filename
            }}</label
          >
          <PaginationControls
            v-bind="candidates"
            :busy="busy"
            @change="(p) => run(() => loadCandidates(p))"
          />
          <button class="primary" :disabled="busy || !checked.length" @click="attach">
            {{ t('Rattacher les emails') }} ({{ checked.length }})
          </button>
        </template>
      </section>
      <OperationalFollowup
        v-if="section === 'followup'"
        :campaign-id="selected.id"
        :request="request"
        :can-write="canWrite"
        :users="users || []"
      />
      <IntelligenceWorkspace
        v-if="section === 'intelligence'"
        :campaign-id="selected.id"
        :request="request"
        :can-write="canWrite"
      />
      <section v-if="section === 'iocs'" class="panel">
        <h2>{{ t('IoC de la campagne') }}</h2>
        <div v-for="ioc in iocs.items" :key="ioc.id" class="case-row">
          <span class="badge">{{ ioc.kind }}</span
          ><a :href="'/iocs/' + ioc.id" @click.exact.prevent="router.push('/iocs/' + ioc.id)">{{
            defang(ioc.value)
          }}</a
          ><small>{{ ioc.analysis_count }} {{ t('Emails') }}</small>
        </div>
        <PaginationControls
          v-bind="iocs"
          :busy="busy"
          @change="
            (p) =>
              run(async () => {
                iocs = await request('/campaigns/' + selected!.id + '/iocs?' + pageQuery(p))
              })
          "
        />
      </section>
      <div v-if="section === 'journal'" class="dashboard-grid">
        <section class="panel">
          <h2>{{ t('Notes d’investigation') }}</h2>
          <form v-if="canWrite" @submit.prevent="addNote">
            <textarea
              v-model="note"
              rows="3"
              required
              maxlength="20000"
              :aria-label="t('Note')"
            /><button class="primary" :disabled="busy">{{ t('Ajouter une note') }}</button>
          </form>
          <article v-for="n in notes" :key="n.id" class="note">
            <small>{{ n.username }} · {{ n.created_at }}</small>
            <p>{{ n.body }}</p>
          </article>
        </section>
        <section class="panel">
          <h2>{{ t('Chronologie') }}</h2>
          <article v-for="event in events.items" :key="event.id" class="timeline">
            <small>{{ event.username || t('Système') }} · {{ event.created_at }}</small>
            <p>{{ t(eventMessages[event.action || ''] || event.action || '') }}</p>
          </article>
          <PaginationControls
            v-bind="events"
            :busy="busy"
            @change="
              (p) =>
                run(async () => {
                  events = await request('/campaigns/' + selected!.id + '/events?' + pageQuery(p))
                })
            "
          />
        </section>
      </div>
    </template>
    <template v-else>
      <section class="panel">
        <h2>{{ t('Campagnes') }}</h2>
        <p class="muted">
          {{ t('Regroupez les emails liés et suivez leur investigation en équipe.') }}
        </p>
        <div class="scope-tabs">
          <button
            :class="{ active: scope === 'mine' }"
            @click="
              scope = 'mine';
              search()
            "
          >
            {{ t('Mes campagnes') }}</button
          ><button
            :class="{ active: scope === 'team' }"
            @click="
              scope = 'team';
              search()
            "
          >
            {{ t('Équipe') }}
          </button>
        </div>
        <form class="filters" @submit.prevent="search()">
          <input
            v-model="query"
            :placeholder="t('Rechercher une campagne')"
            :aria-label="t('Rechercher une campagne')"
          /><select v-model="status" :aria-label="t('Statut')">
            <option value="">{{ t('Tous les statuts') }}</option>
            <option
              v-for="state in ['active', 'investigating', 'resolved', 'closed']"
              :key="state"
              :value="state"
            >
              {{ t(names[state] || state) }}
            </option></select
          ><input v-model="tag" :aria-label="t('Tag')" :placeholder="t('Tag')" /><button
            class="secondary"
          >
            {{ t('Rechercher') }}</button
          ><button v-if="canWrite" type="button" class="primary" @click="showCreate = !showCreate">
            + {{ t('Nouvelle campagne') }}
          </button>
        </form>
        <form v-if="showCreate && canWrite" class="form-grid" @submit.prevent="create">
          <label>{{ t('Nom') }}<input v-model="name" required maxlength="200" /></label
          ><button class="primary" :disabled="busy">{{ t('Créer la campagne') }}</button>
        </form>
        <a
          v-for="item in campaigns.items"
          :key="item.id"
          class="case-row"
          :href="'/campaigns/' + item.id"
          @click.exact.prevent="router.push('/campaigns/' + item.id)"
          ><div>
            <strong>{{ item.name }}</strong
            ><small
              >{{ item.assignee || t('Non assigné') }} · {{ item.analysis_count }}
              {{ t('Emails') }} · {{ item.pending_actions }} {{ t('Actions à faire') }}</small
            >
          </div>
          <span class="badge" :data-state="item.priority">{{
            t(names[item.priority] || item.priority)
          }}</span
          ><span>{{ t(names[item.status] || item.status) }}</span></a
        >
        <p v-if="!campaigns.total" class="empty">{{ t('Aucune campagne trouvée.') }}</p>
        <PaginationControls v-bind="campaigns" :busy="busy" @change="search" />
      </section>
    </template>
  </section>
</template>
