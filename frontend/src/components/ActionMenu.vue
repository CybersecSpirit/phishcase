<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'

import { t } from '@/i18n'
const menu = ref<HTMLDetailsElement | null>(null)
const trigger = ref<HTMLElement | null>(null)
function close(restoreFocus = false) {
  if (menu.value) menu.value.open = false
  if (restoreFocus) trigger.value?.focus()
}
function outside(event: PointerEvent) {
  if (event.target instanceof Node && !menu.value?.contains(event.target)) close()
}
function selected(event: MouseEvent) {
  const target = event.target instanceof Element ? event.target.closest('a,button') : null
  if (target && !target.hasAttribute('disabled')) close(true)
}
onMounted(() => document.addEventListener('pointerdown', outside))
onUnmounted(() => document.removeEventListener('pointerdown', outside))
</script>
<template>
  <details ref="menu" class="action-menu" @keydown.esc.stop.prevent="close(true)">
    <summary ref="trigger">{{ t('Actions') }} <span aria-hidden="true">⌄</span></summary>
    <div class="action-menu-items" @click="selected"><slot /></div>
  </details>
</template>
