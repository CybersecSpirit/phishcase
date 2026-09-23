import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import EnrichmentResults from '@/components/EnrichmentResults.vue'
import InvestigationContext from '@/components/InvestigationContext.vue'
import { setLocale } from '@/i18n'
const provider = {
  name: 'urlscan',
  configured: true,
  lookup_allowed: true,
  lookup_kinds: ['url'],
  submission_allowed: { url: true, file: false }
}
const parsed = {
  eml: {
    header: { header: { 'Authentication-Results': ['untrusted; spf=pass'] }, received: [] },
    bodies: [{ urls: ['https://evil.example/login'] }],
    attachments: []
  }
}
describe('safe investigation surfaces', () => {
  it('performs no provider network action during rendering and requires an explicit submission selection', async () => {
    setLocale('en')
    const request = vi.fn(async (path: string, method?: string) => {
      if (path === '/integrations') return { mode: 'connected', providers: [provider] }
      if (method === 'POST') return {}
      return { items: [], total: 0 }
    })
    const wrapper = mount(EnrichmentResults, {
      props: { request, analysisId: 'analysis-1', result: parsed, canWrite: true }
    })
    await flushPromises()
    expect(request.mock.calls.every(([, method]) => method === undefined)).toBe(true)
    await wrapper.get('select').setValue('urlscan')
    await flushPromises()
    const details = wrapper.get('details'),
      button = details.get('button')
    expect(button.attributes('disabled')).toBeDefined()
    await details.findAll('select')[0]!.setValue('url:https://evil.example/login')
    await details.get('input[type=checkbox]').setValue(true)
    await details.get('form').trigger('submit')
    await flushPromises()
    expect(request).toHaveBeenCalledWith(
      '/analyses/analysis-1/enrichments/submit',
      'POST',
      expect.objectContaining({
        provider: 'urlscan',
        kind: 'url',
        value: 'https://evil.example/login',
        confirm: true,
        visibility: 'private'
      })
    )
    expect(wrapper.find('img').exists()).toBe(false)
    expect(wrapper.find('a[href="https://evil.example/login"]').exists()).toBe(false)
    wrapper.unmount()
  })
  it('defangs hostile URLs and displays header provenance without executing or fetching content', async () => {
    const request = vi.fn(async () => ({ items: [], total: 0, page: 1, page_size: 50, pages: 0 }))
    const wrapper = mount(InvestigationContext, {
      props: { analysisId: 'analysis-1', result: parsed, request }
    })
    await flushPromises()
    expect(wrapper.text()).toContain('hxxps://evil[.]example/login')
    expect(wrapper.text()).toContain('can be forged')
    expect(wrapper.find('img,iframe,script').exists()).toBe(false)
    expect(wrapper.find('a[href="https://evil.example/login"]').exists()).toBe(false)
    expect(request).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })
})
