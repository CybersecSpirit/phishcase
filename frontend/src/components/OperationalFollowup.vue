<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { errorMessage } from '@/errors'
import { t } from '@/i18n'
import type { Request } from '@/workspace'

type User = { id: number; username: string; active: boolean; role: string }
type Action = {
  id: number
  case_id: number | null
  title: string
  owner_id: number | null
  due_date: string | null
  status: string
  proof: string
  revision: number
}
type Reply = {
  id: number
  recipient: string
  subject: string
  body: string
  status: string
  revision: number
  analysis_id: string | null
  transport_error?: string
  reconciliation_proof?: string
  resolved_at?: string
}
const props = defineProps<{
  caseId?: number
  campaignId?: number
  request: Request
  canWrite: boolean
  users: User[]
  analysisId?: string
}>()
const scopePath = computed(() =>
  props.campaignId
    ? '/campaigns/' + props.campaignId
    : props.analysisId
      ? '/analyses/' + props.analysisId
      : '/cases/' + props.caseId
)
const actions = ref<Action[]>([]),
  replies = ref<Reply[]>([]),
  transport = ref(false),
  error = ref(''),
  busy = ref(false)
const action = ref({
  title: '',
  owner_id: null as number | null,
  due_date: '',
  status: 'todo',
  proof: ''
})
const recipient = ref(''),
  subject = ref('Retour sur votre signalement'),
  body = ref(
    'Bonjour,\n\nMerci pour votre signalement.\n\nConclusion de notre analyse :\n\nConsignes à suivre :\n\nL’équipe d’investigation'
  )
const preview = ref<Reply | null>(null),
  editing = ref<Reply | null>(null)
const reconciling = ref<Reply | null>(null),
  reconciliationOutcome = ref('accepted'),
  reconciliationProof = ref('')
const names: Record<string, string> = {
  todo: 'À faire',
  doing: 'En cours',
  done: 'Terminée',
  cancelled: 'Annulée',
  draft: 'Brouillon',
  sending: 'Transmission à vérifier',
  accepted: 'Acceptée par le transport',
  uncertain: 'Transmission à vérifier',
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
async function load() {
  const [a, r] = await Promise.all([
    props.request<Action[]>(scopePath.value + '/actions'),
    props.request<{ items: Reply[]; transport_configured: boolean }>(scopePath.value + '/replies')
  ])
  actions.value = a
  replies.value = r.items
  transport.value = r.transport_configured
}
async function addAction() {
  await run(async () => {
    await props.request(scopePath.value + '/actions', 'POST', {
      ...action.value,
      due_date: action.value.due_date || null
    })
    action.value = { title: '', owner_id: null, due_date: '', status: 'todo', proof: '' }
    await load()
  })
}
async function saveAction(item: Action) {
  await run(async () => {
    await props.request('/actions/' + item.id, 'PUT', { ...item, due_date: item.due_date || null })
    await load()
  })
}
async function draft() {
  await run(async () => {
    const data = {
      recipient: recipient.value,
      subject: subject.value,
      body: body.value,
      analysis_id: props.analysisId || editing.value?.analysis_id || null,
      revision: editing.value?.revision
    }
    const saved = await props.request<Reply>(
      editing.value ? '/replies/' + editing.value.id : scopePath.value + '/replies',
      editing.value ? 'PUT' : 'POST',
      data
    )
    editing.value = null
    await load()
    preview.value = await props.request<Reply>('/replies/' + saved.id + '/preview')
    preview.value.id = saved.id
  })
}
function edit(item: Reply) {
  editing.value = item
  recipient.value = item.recipient
  subject.value = item.subject
  body.value = item.body
  preview.value = null
}
async function showPreview(item: Reply) {
  await run(async () => {
    preview.value = {
      ...(await props.request<Reply>('/replies/' + item.id + '/preview')),
      id: item.id
    }
  })
}
function beginReconciliation(item: Reply) {
  reconciling.value = item
  reconciliationOutcome.value = 'accepted'
  reconciliationProof.value = ''
}
async function reconcile() {
  if (!reconciling.value) return
  await run(async () => {
    await props.request('/replies/' + reconciling.value!.id + '/reconcile', 'POST', {
      revision: reconciling.value!.revision,
      outcome: reconciliationOutcome.value,
      proof: reconciliationProof.value
    })
    reconciling.value = null
    preview.value = null
    await load()
  })
}
async function send() {
  if (!preview.value) return
  await run(async () => {
    await props.request('/replies/' + preview.value!.id + '/send', 'POST', {
      revision: preview.value!.revision
    })
    preview.value = null
    await load()
  })
}
watch(
  () => scopePath.value,
  () => {
    editing.value = null
    preview.value = null
    reconciling.value = null
    void run(load)
  },
  { immediate: true }
)
</script>
<template>
  <section class="followup">
    <div class="panel-title">
      <h2>{{ t('Réponse et actions') }}</h2>
      <button class="text-link" :disabled="busy" @click="run(load)">{{ t('Actualiser') }}</button>
    </div>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <div class="dashboard-grid followup-grid">
      <section class="panel">
        <p class="eyebrow">01 / {{ t('Suivi opérationnel') }}</p>
        <h2>{{ t('Actions à suivre') }}</h2>
        <p class="small muted">
          {{
            t(
              'Chaque action a son responsable, son échéance et un résultat documenté. Les actions ouvertes bloquent la clôture de la campagne.'
            )
          }}
        </p>
        <form v-if="canWrite" class="form-grid" @submit.prevent="addAction">
          <label>{{ t('Action') }}<input v-model="action.title" maxlength="240" required /></label>
          <div class="inline-fields">
            <label
              >{{ t('Responsable')
              }}<select v-model="action.owner_id">
                <option :value="null">{{ t('Non assigné') }}</option>
                <option
                  v-for="u in users.filter((u) => u.active && u.role !== 'viewer')"
                  :key="u.id"
                  :value="u.id"
                >
                  {{ u.username }}
                </option>
              </select></label
            ><label>{{ t('Échéance') }}<input v-model="action.due_date" type="date" /></label>
          </div>
          <button class="primary" :disabled="busy">{{ t('Ajouter l’action') }}</button>
        </form>
        <p v-if="!actions.length" class="empty">{{ t('Aucune action enregistrée.') }}</p>
        <article v-for="item in actions" :key="item.id" class="note action-item">
          <label
            >{{ t('Action')
            }}<input v-model="item.title" :disabled="!canWrite" required maxlength="240"
          /></label>
          <div class="inline-fields">
            <label
              >{{ t('Responsable')
              }}<select v-model="item.owner_id" :disabled="!canWrite">
                <option :value="null">{{ t('Non assigné') }}</option>
                <option
                  v-for="u in users.filter((u) => u.active && u.role !== 'viewer')"
                  :key="u.id"
                  :value="u.id"
                >
                  {{ u.username }}
                </option>
              </select></label
            ><label
              >{{ t('Échéance') }}<input v-model="item.due_date" type="date" :disabled="!canWrite"
            /></label>
          </div>
          <label
            >{{ t('Statut')
            }}<select v-model="item.status" :disabled="!canWrite">
              <option
                v-for="status in ['todo', 'doing', 'done', 'cancelled']"
                :key="status"
                :value="status"
              >
                {{ t(names[status] || status) }}
              </option>
            </select></label
          >
          <label
            >{{ t('Preuve, résultat ou motif d’annulation')
            }}<textarea v-model="item.proof" rows="2" maxlength="20000" :disabled="!canWrite" />
          </label>
          <button v-if="canWrite" class="secondary" :disabled="busy" @click="saveAction(item)">
            {{ t('Enregistrer') }}
          </button>
        </article>
      </section>
      <section class="panel">
        <p class="eyebrow">02 / {{ t('Retour au signalant') }}</p>
        <h2>{{ t('Répondre au signalant') }}</h2>
        <p class="small muted">
          {{
            t(
              'Le destinataire est renseigné par l’analyste : l’expéditeur du message suspect n’est jamais utilisé automatiquement.'
            )
          }}
        </p>
        <p v-if="!transport" class="folio-notice">
          {{ t('Transport non configuré. Vous pouvez préparer et copier le brouillon.') }}
        </p>
        <form v-if="canWrite" class="form-grid" @submit.prevent="draft">
          <label
            >{{ t('Destinataire du signalement')
            }}<input v-model="recipient" type="email" required maxlength="254" autocomplete="off"
          /></label>
          <label>{{ t('Objet') }}<input v-model="subject" required maxlength="240" /></label>
          <label
            >{{ t('Brouillon') }}<textarea v-model="body" rows="8" required maxlength="20000" />
          </label>
          <button class="primary" :disabled="busy">
            {{
              editing ? t('Enregistrer et prévisualiser') : t('Créer le brouillon et prévisualiser')
            }}
          </button>
        </form>
        <section v-if="preview" class="reply-preview" aria-live="polite">
          <p class="eyebrow">{{ t('Prévisualisation') }}</p>
          <strong>{{ preview.recipient }}</strong>
          <h3>{{ preview.subject }}</h3>
          <pre>{{ preview.body }}</pre>
          <button
            v-if="canWrite && preview.status === 'draft'"
            class="primary"
            :disabled="busy || !transport"
            @click="send"
          >
            {{ t('Envoyer cette réponse') }}</button
          ><button class="secondary" @click="preview = null">{{ t('Fermer') }}</button>
          <p class="small muted">
            {{
              t(
                'Un envoi accepté confirme la prise en charge par le transport, pas la lecture ni la livraison au destinataire.'
              )
            }}
          </p>
        </section>
        <article v-for="item in replies" :key="item.id" class="note">
          <span class="badge">{{ t(names[item.status] || item.status) }}</span>
          <h3>{{ item.subject }}</h3>
          <p>{{ item.recipient }}</p>
          <p v-if="item.transport_error" class="error">{{ item.transport_error }}</p>
          <p v-if="item.reconciliation_proof" class="small">
            <strong>{{ t('Preuve du rapprochement') }}</strong
            ><br />{{ item.reconciliation_proof }}
          </p>
          <button class="text-link" @click="showPreview(item)">{{ t('Prévisualiser') }}</button
          ><button
            v-if="canWrite && ['draft', 'failed'].includes(item.status)"
            class="text-link"
            @click="edit(item)"
          >
            {{ t('Modifier le brouillon') }}
          </button>
          <button
            v-if="canWrite && ['sending', 'uncertain'].includes(item.status)"
            class="text-link"
            :disabled="busy"
            @click="beginReconciliation(item)"
          >
            {{ t('Rapprocher le résultat d’envoi') }}
          </button>
          <form
            v-if="canWrite && reconciling?.id === item.id"
            class="form-grid"
            @submit.prevent="reconcile"
          >
            <p class="folio-notice">
              {{
                t(
                  'Vérifiez les journaux du transport. Confirmez une acceptation ou un échec établi, avec une référence ou une preuve. Cette opération ne transmet aucun message.'
                )
              }}
            </p>
            <label
              >{{ t('Résultat vérifié')
              }}<select v-model="reconciliationOutcome">
                <option value="accepted">{{ t('Acceptation confirmée par le transport') }}</option>
                <option value="failed">
                  {{ t('Échec confirmé, aucune acceptation par le transport') }}
                </option>
              </select></label
            >
            <label
              >{{ t('Preuve du rapprochement')
              }}<textarea v-model="reconciliationProof" required maxlength="20000" rows="3" />
            </label>
            <p class="small muted">
              {{
                t(
                  'Après un échec vérifié, vous pourrez modifier le brouillon puis le prévisualiser et l’envoyer explicitement. Aucun nouvel envoi automatique.'
                )
              }}
            </p>
            <button class="primary" :disabled="busy || !reconciliationProof.trim()">
              {{ t('Enregistrer le résultat vérifié') }}
            </button>
            <button type="button" class="secondary" :disabled="busy" @click="reconciling = null">
              {{ t('Annuler') }}
            </button>
          </form>
        </article>
      </section>
    </div>
  </section>
</template>
