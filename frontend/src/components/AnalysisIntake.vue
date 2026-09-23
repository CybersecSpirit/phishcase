<script setup lang="ts">
import { computed, onMounted, onUnmounted,ref } from 'vue'

import { t } from '@/i18n'

type Assessment = { level: string; label: string; explanation: string; missing_engines: string[] }
type Result = {
  id: string
  case_id: number
  subject: string
  filename: string
  status: string
  error?: string
  assessment?: Assessment
}
type Item = {
  key: number
  name: string
  state: 'queued' | 'running' | 'completed' | 'failed'
  result?: Result
  error?: string
}
const props = defineProps<{
  uploadFile: (file: File) => Promise<Result>
  canUpload: boolean
  getAnalysis: (id: string) => Promise<Result>
}>()
const emit = defineEmits<{ completed: []; open: [id: string]; case: [id: number] }>()
const items = ref<Item[]>([]),
  active = ref(false),
  dragging = ref(false),
  message = ref('')
const finished = computed(
  () => items.value.filter((i) => i.state === 'completed' || i.state === 'failed').length
)
let nextKey = 0
async function receive(files: File[]) {
  if (!props.canUpload || active.value || !files.length) return
  if (files.length > 20) {
    message.value = t('Sélectionnez jusqu’à 20 emails par envoi.')
    return
  }
  message.value = ''
  active.value = true
  const jobs = files.map((file) => ({
    file,
    item: { key: nextKey++, name: file.name, state: 'queued' as Item['state'] } as Item
  }))
  items.value.push(...jobs.map((j) => j.item))
  try {
    for (const job of jobs) {
      const item = items.value.find((i) => i.key === job.item.key)!
      if (
        !/\.(eml|msg)$/i.test(job.file.name) ||
        !job.file.size ||
        job.file.size > 20 * 1024 * 1024
      ) {
        item.state = 'failed'
        item.error = t('Fichier EML/MSG non vide, de 20 Mo maximum.')
        continue
      }
      item.state = 'running'
      try {
        const r = await props.uploadFile(job.file)
        item.result = {
          id: r.id,
          case_id: r.case_id,
          subject: r.subject,
          filename: r.filename,
          status: r.status,
          assessment: r.assessment,
          error: r.error
        }
        item.state = ['queued', 'running', 'completed', 'failed'].includes(r.status)
          ? (r.status as Item['state'])
          : 'queued'
        item.error = r.error
        emit('completed')
      } catch (e) {
        item.state = 'failed'
        item.error = e instanceof Error ? e.message : t('Échec de l’envoi')
      }
    }
  } finally {
    active.value = false
  }
}
function choose(event: Event) {
  const input = event.target as HTMLInputElement
  const files = Array.from(input.files || [])
  input.value = ''
  void receive(files)
}
function drop(event: DragEvent) {
  dragging.value = false
  void receive(Array.from(event.dataTransfer?.files || []))
}
let timer: ReturnType<typeof setInterval> | undefined
let polling = false
async function poll() {
  if (polling) return
  polling = true
  try {
    const pending = items.value.filter(
      (item) => item.result && ['queued', 'running'].includes(item.state)
    )
    await Promise.all(
      pending.map(async (item) => {
        try {
          const result = await props.getAnalysis(item.result!.id)
          item.result = result
          item.state = result.status as Item['state']
          item.error = result.error
          if (result.status === 'completed' || result.status === 'failed') emit('completed')
        } catch {
          /* transient network errors do not mark server jobs failed */
        }
      })
    )
  } finally {
    polling = false
  }
}
onMounted(() => {
  timer = setInterval(() => void poll(), 3000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
function clear() {
  if (!active.value) items.value = []
}
</script>

<template>
  <section class="intake">
    <div
      v-if="canUpload"
      class="dropzone"
      :class="{ dragging, processing: active }"
      @dragover.prevent="dragging = !active"
      @dragleave.prevent="dragging = false"
      @drop.prevent="drop"
    >
      <div class="intake-icon" aria-hidden="true">↥</div>
      <h2>{{ active ? t('Envoi de vos emails…') : t('Glissez vos emails ici') }}</h2>
      <p>{{ t('EML ou MSG · un ou plusieurs fichiers · 20 Mo par email') }}</p>
      <label class="primary intake-picker"
        >{{ active ? t('Envoi en cours…') : t('Choisir mes emails')
        }}<input
          :aria-label="t('Choisir mes emails')"
          type="file"
          accept=".eml,.msg"
          multiple
          :disabled="active"
          @change="choose"
      /></label>
      <small>
        {{
          t('Chaque email est enregistré automatiquement dans un dossier « date · objet du mail ».')
        }}
      </small>
    </div>
    <p v-else class="panel">
      {{
        t('Votre compte permet de consulter les résultats. Un analyste peut déposer des emails.')
      }}
    </p>
    <p v-if="message" class="error" role="alert">{{ message }}</p>
    <section
      v-if="items.length"
      class="panel intake-results"
      aria-live="polite"
      :aria-busy="active"
    >
      <div class="panel-title">
        <h2>
          {{ t('Vos résultats') }}
          <span class="muted small">{{ finished }} / {{ items.length }}</span>
        </h2>
        <button v-if="!active" @click="clear">{{ t('Effacer cette liste') }}</button>
      </div>
      <p v-if="active" class="small muted">
        {{
          t(
            'Gardez cet onglet ouvert pendant l’envoi. Après réception, l’analyse continue côté serveur même si vous fermez le navigateur.'
          )
        }}
      </p>
      <article
        v-for="item in items"
        :key="item.key"
        class="intake-result"
        :data-state="item.result?.assessment?.level || item.state"
      >
        <div class="intake-result-main">
          <strong>{{ item.result?.subject || item.name }}</strong
          ><small class="muted">{{ item.name }}</small>
        </div>
        <div class="intake-result-verdict">
          <span class="badge" :data-state="item.result?.assessment?.level || item.state">{{
            item.state === 'queued'
              ? t('En attente')
              : item.state === 'running'
                ? t('Analyse en cours…')
                : item.state === 'failed'
                  ? t('Analyse impossible')
                  : t(item.result?.assessment?.label || 'Résultat disponible')
          }}</span>
          <p>{{ item.error || t(item.result?.assessment?.explanation || '') }}</p>
          <p v-if="item.result?.assessment?.missing_engines.length" class="small">
            {{ t('Contrôles sans résultat :') }}
            {{ item.result.assessment.missing_engines.join(', ') }}
          </p>
        </div>
        <div v-if="item.result" class="intake-result-actions">
          <button class="text-link" @click="emit('open', item.result!.id)">
            {{ t('Voir le résultat →') }}</button
          ><button class="text-link" @click="emit('case', item.result!.case_id)">
            {{ t('Dossier #') }} {{ item.result.case_id }}
          </button>
        </div>
      </article>
      <p class="small muted">
        {{
          t(
            'Les résultats restent disponibles dans Analyses et Dossiers, même si vous effacez cette liste.'
          )
        }}
      </p>
    </section>
  </section>
</template>
