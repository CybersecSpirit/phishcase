<script setup lang="ts">
import { computed, ref } from 'vue'

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
const props = defineProps<{ uploadFile: (file: File) => Promise<Result>; canUpload: boolean }>()
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
    message.value = 'Sélectionnez jusqu’à 20 emails par envoi.'
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
        item.error = 'Fichier EML/MSG non vide, de 20 Mo maximum.'
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
        item.state = r.status === 'completed' ? 'completed' : 'failed'
        item.error = r.error
        emit('completed')
      } catch (e) {
        item.state = 'failed'
        item.error = e instanceof Error ? e.message : 'Échec de l’envoi'
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
      <h2>{{ active ? 'Analyse de vos emails en cours…' : 'Glissez vos emails ici' }}</h2>
      <p>EML ou MSG · un ou plusieurs fichiers · 20 Mo par email</p>
      <label class="primary intake-picker"
        >{{ active ? 'Traitement en cours…' : 'Choisir mes emails'
        }}<input
          aria-label="Choisir mes emails"
          type="file"
          accept=".eml,.msg"
          multiple
          :disabled="active"
          @change="choose"
      /></label>
      <small
        >Chaque email est enregistré automatiquement dans un dossier « date · objet du mail
        ».</small
      >
    </div>
    <p v-else class="panel">
      Votre compte permet de consulter les résultats. Un analyste peut déposer des emails.
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
          Vos résultats <span class="muted small">{{ finished }} / {{ items.length }}</span>
        </h2>
        <button v-if="!active" @click="clear">Effacer cette liste</button>
      </div>
      <p v-if="active" class="small muted">
        Les fichiers sont traités l’un après l’autre. Gardez cet onglet ouvert jusqu’à la fin de
        l’envoi.
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
              ? 'En attente'
              : item.state === 'running'
                ? 'Analyse en cours…'
                : item.state === 'failed'
                  ? 'Analyse impossible'
                  : item.result?.assessment?.label || 'Résultat disponible'
          }}</span>
          <p>{{ item.error || item.result?.assessment?.explanation }}</p>
          <p v-if="item.result?.assessment?.missing_engines.length" class="small">
            Contrôles sans résultat : {{ item.result.assessment.missing_engines.join(', ') }}
          </p>
        </div>
        <div v-if="item.result" class="intake-result-actions">
          <button class="text-link" @click="emit('open', item.result!.id)">
            Voir le résultat →</button
          ><button class="text-link" @click="emit('case', item.result!.case_id)">
            Dossier #{{ item.result.case_id }}
          </button>
        </div>
      </article>
      <p class="small muted">
        Les résultats restent disponibles dans Analyses et Dossiers, même si vous effacez cette
        liste.
      </p>
    </section>
  </section>
</template>
