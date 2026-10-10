<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { t } from '@/i18n'
const props = defineProps<{ task: string }>()
const guides: Record<string, { title: string; steps: string[] }> = {
  intake: {
    title: 'Du dépôt à la qualification',
    steps: [
      'Déposez un ou plusieurs fichiers EML / MSG. Chaque original est conservé dans son dossier et assigné à votre compte.',
      'Ouvrez le résultat : lisez le message neutralisé, examinez les preuves puis les contrôles automatiques.',
      'Enregistrez votre verdict, votre confiance et une justification. Préparez ensuite le retour au signalant et les actions.'
    ]
  },
  decision: {
    title: 'Prendre une décision traçable',
    steps: [
      'Lisez l’original neutralisé et confrontez les indices : expéditeur, liens, pièces jointes et en-têtes.',
      'Les résultats automatiques sont des éléments de preuve. Choisissez l’un des huit verdicts et documentez vos raisons.',
      'L’historique conserve chaque décision. Une modification concurrente vous invite à recharger ; une réouverture exige une justification.'
    ]
  },
  cases: {
    title: 'Travailler en équipe',
    steps: [
      'Passez de « Mes dossiers » à la vue d’équipe pour répartir les investigations.',
      'Attribuez le dossier à un analyste. Les notes, décisions et actions restent visibles à l’équipe selon ses droits.',
      'Expliquez les rapprochements entre messages et campagnes ; terminez les actions et qualifiez les messages avant la clôture.'
    ]
  },
  campaigns: {
    title: 'Construire une corrélation',
    steps: [
      'Créez une campagne d’investigation puis rattachez les dossiers pertinents.',
      'Examinez les indicateurs partagés et les raisons exactes des similarités. Un signal commun est une piste, pas une attribution.',
      'Documentez les sources, faits, contre-indices et hypothèses dans le renseignement. Les dossiers restent distincts.'
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
