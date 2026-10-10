<script setup lang="ts">
import { computed } from 'vue'

import { FetchError } from '@/api'
import { errorMessage, RequestError } from '@/errors'
import type { ErrorDataType } from '@/schemas'

const props = defineProps({
  error: {
    type: Error,
    required: true
  },
  disposable: {
    type: Boolean,
    default: false
  }
})
const emits = defineEmits(['dispose'])

const data = computed<ErrorDataType | undefined>(() => {
  if (props.error instanceof FetchError && props.error.response) {
    return props.error.response.data as ErrorDataType
  }
  return undefined
})

const dispose = () => {
  emits('dispose')
}
const display = computed(() =>
  props.error instanceof FetchError
    ? errorMessage(new RequestError(data.value?.detail, props.error.status))
    : errorMessage(props.error)
)
</script>

<template>
  <div class="alert alert-error">
    <button
      class="btn btn-sm btn-circle btn-ghost absolute right-2 top-2"
      v-if="disposable"
      @click="dispose"
    >
      ✕
    </button>
    <p>{{ display }}</p>
  </div>
</template>
