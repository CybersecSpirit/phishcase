import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import AnalystDecision from '@/components/AnalystDecision.vue'
import { setLocale } from '@/i18n'
describe('human conclusions', () => {
  it('saves a justified human verdict and shows its auditable history separately', async () => {
    setLocale('en')
    let saved = false
    const decision = {
      id: 1,
      verdict: 'phishing',
      confidence: 90,
      justification: 'Verified fraudulent destination',
      username: 'analyst',
      created_at: '2026-09-23',
      action: 'decided'
    }
    const request = vi.fn(async (path: string, method?: string) => {
      if (method === 'PUT') {
        saved = true
        return decision
      }
      if (path.endsWith('/decision')) return { current: saved ? decision : null }
      return {
        items: saved ? [decision] : [],
        total: saved ? 1 : 0,
        page: 1,
        page_size: 50,
        pages: saved ? 1 : 0
      }
    })
    const wrapper = mount(AnalystDecision, {
      props: { analysisId: 'evidence-1', request, canWrite: true }
    })
    await flushPromises()
    expect(wrapper.text()).toContain('No active analyst conclusion')
    await wrapper.get('select').setValue('phishing')
    await wrapper.get('input[type=number]').setValue(90)
    await wrapper.get('textarea').setValue(decision.justification)
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(request).toHaveBeenCalledWith('/analyses/evidence-1/decision', 'PUT', {
      verdict: 'phishing',
      confidence: 90,
      justification: decision.justification
    })
    expect(wrapper.text()).toContain('Verified fraudulent destination')
    expect(wrapper.text()).toContain('Decision history (1)')
    expect(wrapper.text()).toContain('separate from automated results')
    wrapper.unmount()
  })
  it('does not expose editing controls to a read-only user', async () => {
    const request = vi.fn(async (path: string) =>
      path.endsWith('/decision')
        ? { current: null }
        : { items: [], total: 0, page: 1, pages: 0, page_size: 50 }
    )
    const wrapper = mount(AnalystDecision, {
      props: { analysisId: 'evidence-1', request, canWrite: false }
    })
    await flushPromises()
    expect(wrapper.find('form').exists()).toBe(false)
    expect(request.mock.calls.every((call) => call.length === 1)).toBe(true)
    wrapper.unmount()
  })
})
