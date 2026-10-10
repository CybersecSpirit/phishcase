<script setup lang="ts">
import { t } from '@/i18n'
defineProps<{ page: number; pages: number; total: number; busy?: boolean }>()
defineEmits<{ change: [page: number] }>()
</script>
<template>
  <nav class="pagination" :aria-label="t('Pagination')">
    <span>{{
      t('{total} résultats · page {page} sur {pages}', { total, page, pages: Math.max(1, pages) })
    }}</span>
    <button class="secondary" :disabled="busy || page <= 1" @click="$emit('change', page - 1)">
      {{ t('Précédent') }}
    </button>
    <button class="secondary" :disabled="busy || page >= pages" @click="$emit('change', page + 1)">
      {{ t('Suivant') }}
    </button>
  </nav>
</template>
