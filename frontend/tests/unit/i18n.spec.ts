import { describe, expect, it } from 'vitest'
import { nextTick } from 'vue'

import { locale, setLocale, setLocaleUser, t } from '@/i18n'
import { messages } from '@/i18n/messages'
describe('workspace localization', () => {
  it('changes all shared messages reactively and keeps placeholders', async () => {
    setLocale('en')
    await nextTick()
    expect(t('Décision analyste')).toBe('Analyst decision')
    expect(
      t('{total} résultats · page {page} sur {pages}', { total: 601, page: 2, pages: 13 })
    ).toBe('601 results · page 2 of 13')
    expect(document.documentElement.lang).toBe('en')
    setLocale('fr')
    expect(t('Décision analyste')).toBe('Décision analyste')
  })
  it('persists the chosen locale separately for each signed-in user', async () => {
    setLocaleUser(200, 'fr')
    await nextTick()
    setLocaleUser(201, 'en')
    await nextTick()
    setLocaleUser(200)
    expect(locale.value).toBe('fr')
    setLocaleUser(201)
    expect(locale.value).toBe('en')
  })
  it('has matching placeholder names in every translation', () => {
    for (const [key, value] of Object.entries(messages)) {
      expect([...key.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort(), key).toEqual(
        [...value.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()
      )
    }
  })
})
