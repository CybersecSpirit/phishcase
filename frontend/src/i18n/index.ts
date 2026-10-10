import { ref, watch } from 'vue'

import { messages } from './messages'
export type Locale = 'fr' | 'en'
let userKey = 'guest'
function storageKey() {
  return 'phishcase.locale.' + userKey
}
function readLocale(): Locale {
  try {
    const saved = localStorage.getItem(storageKey())
    if (saved === 'fr' || saved === 'en') return saved
  } catch {
    /* private browser */
  }
  return typeof navigator !== 'undefined' && navigator.language.startsWith('fr') ? 'fr' : 'en'
}
export const locale = ref<Locale>(readLocale())
export function setLocale(value: string) {
  if (value === 'fr' || value === 'en') locale.value = value
}
export function setLocaleUser(id?: number, preferred?: string) {
  userKey = id === undefined ? 'guest' : String(id)
  locale.value = preferred === 'fr' || preferred === 'en' ? preferred : readLocale()
  try {
    localStorage.setItem(storageKey(), locale.value)
  } catch {
    /* private browser */
  }
}
watch(
  locale,
  (value) => {
    document.documentElement.lang = value
    try {
      localStorage.setItem(storageKey(), value)
    } catch {
      /* private browser */
    }
  },
  { immediate: true, flush: 'sync' }
)
export function t(key: string, params: Record<string, string | number> = {}): string {
  const translated = locale.value === 'en' ? messages[key] || key : key
  return translated.replace(/\{(\w+)\}/g, (match, name: string) => String(params[name] ?? match))
}
