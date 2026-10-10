<script setup lang="ts">
import { ref, watch } from 'vue'
import { errorMessage } from '@/errors'
import { t } from '@/i18n'
import router from '@/router'
import { emptyPage, type Page, type Request } from '@/workspace'
import PaginationControls from './PaginationControls.vue'
type Observation = {
  id: number
  case_id: number | null
  campaign_id: number | null
  title: string
  source: string
  facts: string
  counter_evidence: string
  hypothesis: string
  confidence: number
  observed_at: string
  revision: number
  case_title?: string
  campaign_name?: string
  username?: string
}
const props = defineProps<{ request: Request; canWrite: boolean; caseId?: number }>()
const items = ref(emptyPage<Observation>()),
  cases = ref<{ id: number; title: string }[]>([]),
  campaigns = ref<{ id: number; name: string }[]>([]),
  error = ref(''),
  busy = ref(false),
  show = ref(false),
  editing = ref<number | null>(null)
const blank = () => ({
  case_id: props.caseId || null,
  campaign_id: null as number | null,
  title: '',
  source: '',
  facts: '',
  counter_evidence: '',
  hypothesis: '',
  confidence: 0,
  observed_at: new Date().toISOString().slice(0, 10),
  revision: undefined as number | undefined
})
const form = ref(blank())
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
async function load(page = 1) {
  items.value = await props.request<Page<Observation>>(
    '/intelligence?page=' + page + (props.caseId ? '&case_id=' + props.caseId : '')
  )
}
async function options() {
  const [c, p] = await Promise.all([
    props.request<Page<{ id: number; title: string }>>('/cases?page=1&page_size=200'),
    props.request<Page<{ id: number; name: string }>>('/campaigns?page=1&page_size=200')
  ])
  cases.value = c.items
  campaigns.value = p.items
}
async function save() {
  await run(async () => {
    await props.request(
      editing.value ? '/intelligence/' + editing.value : '/intelligence',
      editing.value ? 'PUT' : 'POST',
      form.value
    )
    form.value = blank()
    editing.value = null
    show.value = false
    await load()
  })
}
function cancel() {
  show.value = false
  editing.value = null
  form.value = blank()
}
function edit(item: Observation) {
  editing.value = item.id
  form.value = { ...item }
  show.value = true
}
watch(
  () => props.caseId,
  () =>
    void run(async () => {
      await Promise.all([load(), options()])
    }),
  { immediate: true }
)
</script>
<template>
  <section class="intelligence-workspace">
    <div class="panel-title">
      <div>
        <p class="eyebrow">{{ t('Fuites / campagnes / contexte') }}</p>
        <h2>{{ t('Renseignement documenté') }}</h2>
      </div>
      <button v-if="canWrite" class="primary" @click="show = !show">
        {{ t('Documenter une observation') }}
      </button>
    </div>
    <p class="small muted">
      {{
        t(
          'Consignez une fuite, une source et les correspondances observées. Séparez les faits, les contre-indices et les hypothèses. La confiance est celle de l’analyste ; aucun lien ni attribution n’est déduit automatiquement.'
        )
      }}
    </p>
    <p v-if="error" class="error" role="alert">
      {{ error }}
      <button class="secondary" @click="run(() => load())">{{ t('Actualiser') }}</button>
    </p>
    <form v-if="show && canWrite" class="panel form-grid" @submit.prevent="save">
      <label>{{ t('Observation') }}<input v-model="form.title" required maxlength="240" /></label>
      <div class="inline-fields">
        <label
          >{{ t('Dossier')
          }}<select v-model="form.case_id">
            <option :value="null">{{ t('Sans rattachement') }}</option>
            <option v-for="c in cases" :key="c.id" :value="c.id">
              #{{ c.id }} · {{ c.title }}
            </option>
          </select></label
        ><label
          >{{ t('Campagne')
          }}<select v-model="form.campaign_id">
            <option :value="null">{{ t('Sans rattachement') }}</option>
            <option v-for="c in campaigns" :key="c.id" :value="c.id">{{ c.name }}</option>
          </select></label
        >
      </div>
      <label
        >{{ t('Source / référence')
        }}<input v-model="form.source" required maxlength="2000" /><small>{{
          t('Référence conservée en texte. Aucune consultation distante automatique.')
        }}</small></label
      >
      <label
        >{{ t('Faits observés et correspondances vérifiables')
        }}<textarea v-model="form.facts" rows="4" required maxlength="20000" />
      </label>
      <label
        >{{ t('Contre-indices et limites')
        }}<textarea v-model="form.counter_evidence" rows="3" maxlength="20000" />
      </label>
      <label
        >{{ t('Hypothèse de rapprochement')
        }}<textarea v-model="form.hypothesis" rows="3" maxlength="20000" />
      </label>
      <div class="inline-fields">
        <label
          >{{ t('Date d’observation')
          }}<input v-model="form.observed_at" type="date" required /></label
        ><label
          >{{ t('Confiance analyste (%)')
          }}<input v-model.number="form.confidence" type="number" min="0" max="100" required
        /></label>
      </div>
      <div>
        <button class="primary" :disabled="busy">{{ t('Enregistrer l’observation') }}</button
        ><button class="secondary" type="button" @click="cancel">
          {{ t('Annuler') }}
        </button>
      </div>
    </form>
    <p v-if="!items.total" class="empty">
      {{ t('Aucune observation documentée. Ajoutez une source utile à vos investigations.') }}
    </p>
    <article v-for="item in items.items" :key="item.id" class="panel intelligence-record">
      <div class="panel-title">
        <h2>{{ item.title }}</h2>
        <span class="folio-reference"
          >{{ item.observed_at }} / {{ item.confidence }} % {{ t('confiance analyste') }}</span
        >
      </div>
      <p class="folio-meta">{{ item.source }} · {{ item.username }}</p>
      <div class="dashboard-grid">
        <div>
          <h3>{{ t('Faits') }}</h3>
          <p class="preserve-lines">{{ item.facts }}</p>
          <h3>{{ t('Contre-indices') }}</h3>
          <p class="preserve-lines">{{ item.counter_evidence || '—' }}</p>
        </div>
        <div>
          <h3>{{ t('Hypothèse') }}</h3>
          <p class="preserve-lines">{{ item.hypothesis || '—' }}</p>
          <p v-if="item.case_id">
            <a
              :href="'/cases/' + item.case_id"
              @click.exact.prevent="router.push('/cases/' + item.case_id)"
              >{{ item.case_title || '#' + item.case_id }}</a
            >
          </p>
          <p v-if="item.campaign_id">
            <a
              :href="'/campaigns/' + item.campaign_id"
              @click.exact.prevent="router.push('/campaigns/' + item.campaign_id)"
              >{{ item.campaign_name || '#' + item.campaign_id }}</a
            >
          </p>
        </div>
      </div>
      <button v-if="canWrite" class="text-link" @click="edit(item)">{{ t('Modifier') }}</button>
    </article>
    <PaginationControls v-bind="items" :busy="busy" @change="(p) => run(() => load(p))" />
  </section>
</template>
