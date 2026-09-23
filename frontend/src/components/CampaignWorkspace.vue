<script setup lang="ts">
import { ref, watch } from 'vue'

import { t } from '@/i18n'
import router from '@/router'
import { defang, emptyPage, eventMessages, type Page, pageQuery, type Request } from '@/workspace'

import PaginationControls from './PaginationControls.vue'
type Campaign = {
  id: number
  name: string
  description: string
  tags: string[]
  status: string
  verdict: string | null
  case_count: number
  analysis_count: number
}
type CaseLink = { id: number; title: string; analysis_count: number }
type IOC = { id: number; kind: string; value: string; case_count: number }
type Event = { id: number; action: string; detail: string; created_at: string; username: string }
const props = defineProps<{ request: Request; canWrite: boolean }>()
const campaigns = ref(emptyPage<Campaign>()),
  selected = ref<Campaign | null>(null),
  cases = ref(emptyPage<CaseLink>()),
  iocs = ref(emptyPage<IOC>()),
  events = ref(emptyPage<Event>())
const name = ref(''),
  description = ref(''),
  tags = ref(''),
  query = ref(''),
  caseId = ref<number | null>(null),
  create = ref(false),
  busy = ref(false),
  error = ref('')
async function run(action: () => Promise<unknown>) {
  busy.value = true
  error.value = ''
  try {
    await action()
  } catch (e) {
    error.value = e instanceof Error ? e.message : t('Erreur inattendue')
  } finally {
    busy.value = false
  }
}
async function load(page = 1) {
  campaigns.value = await props.request<Page<Campaign>>(
    '/campaigns?' + pageQuery(page, { q: query.value })
  )
}
async function details(id: number) {
  selected.value = await props.request<Campaign>('/campaigns/' + id)
  tags.value = selected.value.tags.join(', ')
  await Promise.all([loadCases(), loadIocs(), loadEvents()])
}
async function loadCases(page = 1) {
  cases.value = await props.request<Page<CaseLink>>(
    '/campaigns/' + selected.value!.id + '/cases?' + pageQuery(page)
  )
}
async function loadIocs(page = 1) {
  iocs.value = await props.request<Page<IOC>>(
    '/campaigns/' + selected.value!.id + '/iocs?' + pageQuery(page)
  )
}
async function loadEvents(page = 1) {
  events.value = await props.request<Page<Event>>(
    '/campaigns/' + selected.value!.id + '/events?' + pageQuery(page)
  )
}
async function save() {
  await run(async () => {
    const campaign = await props.request<Campaign>(
      '/campaigns' + (selected.value ? '/' + selected.value.id : ''),
      selected.value ? 'PUT' : 'POST',
      {
        name: selected.value?.name || name.value,
        description: selected.value?.description ?? description.value,
        tags: tags.value
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean),
        status: selected.value?.status || 'active',
        verdict: selected.value?.verdict || null
      }
    )
    create.value = false
    await router.push('/campaigns/' + campaign.id)
    await details(campaign.id)
  })
}
async function link(id: number, remove = false) {
  await run(async () => {
    await props.request(
      '/campaigns/' + selected.value!.id + '/cases/' + id,
      remove ? 'DELETE' : 'PUT'
    )
    caseId.value = null
    await details(selected.value!.id)
  })
}
watch(
  () => router.currentRoute.value.fullPath,
  () => {
    const route = router.currentRoute.value
    if (!route.path.startsWith('/campaigns')) return
    query.value = typeof route.query.q === 'string' ? route.query.q : ''
    selected.value = null
    void run(() =>
      route.params.id ? details(Number(route.params.id)) : load(Number(route.query.page || 1))
    )
  },
  { immediate: true }
)
async function pageList(page: number) {
  await router.push({ path: '/campaigns', query: { page, q: query.value } })
}
</script>
<template>
  <section>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <template v-if="selected">
      <a href="/campaigns" class="back" @click.exact.prevent="router.push('/campaigns')"
        >← {{ t('Toutes les campagnes') }}</a
      >
      <form class="panel form-grid" @submit.prevent="save">
        <h2>{{ t('Campagne') }} #{{ selected.id }}</h2>
        <label
          >{{ t('Nom')
          }}<input v-model="selected.name" required maxlength="200" :disabled="!canWrite" /></label
        ><label
          >{{ t('Description')
          }}<textarea
            v-model="selected.description"
            rows="3"
            :disabled="!canWrite"
          ></textarea></label
        ><label
          >{{ t('Tags séparés par des virgules')
          }}<input v-model="tags" :disabled="!canWrite" /></label
        ><label
          >{{ t('Statut')
          }}<select v-model="selected.status" :disabled="!canWrite">
            <option value="active">{{ t('Active') }}</option>
            <option value="closed">{{ t('Close') }}</option>
          </select></label
        ><button v-if="canWrite" class="primary" :disabled="busy">{{ t('Enregistrer') }}</button>
      </form>
      <section class="panel">
        <h2>{{ t('Dossiers associés') }} ({{ cases.total }})</h2>
        <form v-if="canWrite" class="filters" @submit.prevent="caseId && link(caseId)">
          <input
            v-model="caseId"
            type="number"
            min="1"
            required
            :placeholder="t('Numéro du dossier')"
            :aria-label="t('Numéro du dossier')"
          /><button class="secondary" :disabled="busy">{{ t('Rattacher le dossier') }}</button>
        </form>
        <div v-for="item in cases.items" :key="item.id" class="case-row">
          <a :href="'/cases/' + item.id" @click.exact.prevent="router.push('/cases/' + item.id)"
            >#{{ item.id }} · {{ item.title }}</a
          ><button v-if="canWrite" class="secondary" :disabled="busy" @click="link(item.id, true)">
            {{ t('Détacher') }}
          </button>
        </div>
        <PaginationControls v-bind="cases" :busy="busy" @change="(p) => run(() => loadCases(p))" />
      </section>
      <section class="panel">
        <h2>{{ t('IOC communs') }}</h2>
        <p class="muted small">
          {{ t('Indicateurs présents dans au moins deux dossiers de cette campagne.') }}
        </p>
        <div v-for="ioc in iocs.items" :key="ioc.id" class="case-row">
          <span class="badge">{{ ioc.kind }}</span
          ><a :href="'/iocs/' + ioc.id" @click.exact.prevent="router.push('/iocs/' + ioc.id)">{{
            defang(ioc.value)
          }}</a
          ><small>{{ ioc.case_count }} {{ t('Dossiers') }}</small>
        </div>
        <PaginationControls v-bind="iocs" :busy="busy" @change="(p) => run(() => loadIocs(p))" />
      </section>
      <section class="panel">
        <h2>{{ t('Chronologie') }}</h2>
        <article v-for="event in events.items" :key="event.id" class="note">
          <strong>{{ t(eventMessages[event.action] || event.action) }}</strong>
          <details v-if="event.detail">
            <summary>{{ t('Détails de l’événement') }}</summary>
            <pre>{{ event.detail }}</pre>
          </details>
          <small>{{ event.username }} · {{ event.created_at }}</small>
        </article>
        <PaginationControls
          v-bind="events"
          :busy="busy"
          @change="(p) => run(() => loadEvents(p))"
        />
      </section>
    </template>
    <template v-else
      ><form class="filters" @submit.prevent="pageList(1)">
        <input
          v-model="query"
          :placeholder="t('Rechercher une campagne')"
          :aria-label="t('Rechercher une campagne')"
        /><button class="secondary">{{ t('Rechercher') }}</button
        ><button v-if="canWrite" type="button" class="primary" @click="create = !create">
          + {{ t('Nouvelle campagne') }}
        </button>
      </form>
      <form v-if="create" class="panel form-grid" @submit.prevent="save">
        <label>{{ t('Nom') }}<input v-model="name" required maxlength="200" /></label
        ><label>{{ t('Description') }}<textarea v-model="description" rows="3"></textarea></label
        ><label>{{ t('Tags séparés par des virgules') }}<input v-model="tags" /></label
        ><button class="primary" :disabled="busy">{{ t('Créer la campagne') }}</button>
      </form>
      <section class="panel">
        <a
          v-for="item in campaigns.items"
          :key="item.id"
          class="case-row"
          :href="'/campaigns/' + item.id"
          @click.exact.prevent="router.push('/campaigns/' + item.id)"
          ><div>
            <strong>{{ item.name }}</strong
            ><small>{{ item.description }}</small>
          </div>
          <span
            >{{ item.case_count }} {{ t('Dossiers') }} · {{ item.analysis_count }}
            {{ t('Analyses') }}</span
          ></a
        >
        <p v-if="!campaigns.total" class="empty">{{ t('Aucune campagne trouvée.') }}</p>
        <PaginationControls v-bind="campaigns" :busy="busy" @change="pageList" /></section
    ></template>
  </section>
</template>
