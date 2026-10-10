<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { t } from '@/i18n'
const props = defineProps<{ task: string }>()
const guides: Record<string, { title: string; steps: string[] }> = {
  intake: {
    title: 'Du dépôt à la qualification',
    steps: [
      'Déposez un ou plusieurs fichiers EML / MSG. Chaque original et son analyse sont conservés sans créer de dossier.',
      'Ouvrez le résultat : lisez le message neutralisé, examinez les preuves puis les contrôles automatiques.',
      'Enregistrez votre verdict, votre confiance et une justification. Préparez ensuite le retour au signalant et les actions.'
    ]
  },
  decision: {
    title: 'Prendre une décision traçable',
    steps: [
      'Lisez l’original neutralisé et confrontez les éléments : expéditeur, liens, pièces jointes et en-têtes.',
      'Les résultats automatiques sont des éléments de preuve. Choisissez l’un des huit verdicts et documentez vos raisons.',
      'L’historique conserve chaque décision. Une modification concurrente vous invite à recharger ; une réouverture exige une justification.'
    ]
  },
  campaigns: {
    title: 'Construire une corrélation',
    steps: [
      'Créez une campagne d’investigation puis sélectionnez les emails pertinents.',
      'Examinez les IoC partagés et les raisons exactes des similarités. Un signal commun est une piste, pas une attribution.',
      'Documentez les sources, faits, limites et hypothèses dans le renseignement. Chaque email conserve son verdict.'
    ]
  }
}
const step = ref(0),
  open = ref(false),
  guide = computed(() => guides[props.task])
const hasNext = computed(() => guide.value && step.value + 1 < guide.value.steps.length)
function toggle() {
  open.value = !open.value
  step.value = 0
}
function next() {
  if (hasNext.value) step.value++
  else open.value = false
}
watch(
  () => props.task,
  () => {
    open.value = false
    step.value = 0
  }
)
</script>
<template>
  <div v-if="guide" class="task-guide">
    <button class="text-link" :aria-expanded="open" @click="toggle">
      {{ open ? t('Fermer le guide') : t('Guide de cette tâche') }} ↗
    </button>
    <section v-if="open" class="folio-guide" aria-live="polite">
      <p class="folio-meta">{{ step + 1 }} / {{ guide.steps.length }}</p>
      <h2>{{ t(guide.title) }}</h2>
      <p>{{ t(guide.steps[step] || '') }}</p>
      <button v-if="step > 0" class="secondary" @click="step--">{{ t('Précédent') }}</button
      ><button class="primary" @click="next()">{{ hasNext ? t('Suivant') : t('Terminer') }}</button>
    </section>
  </div>
</template>
