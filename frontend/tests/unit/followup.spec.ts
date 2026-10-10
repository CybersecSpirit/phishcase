import { mount, flushPromises } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import OperationalFollowup from '@/components/OperationalFollowup.vue'
import { setLocale } from '@/i18n'
import type { Request } from '@/workspace'

const reply = {
  id: 7,
  recipient: 'reporter@example.org',
  subject: 'Reviewed',
  body: '<script>alert(1)</script>',
  status: 'draft',
  revision: 1,
  analysis_id: null
}
function fixture(transport = false, status = 'draft') {
  setLocale('fr')
  const request = vi.fn(async (path: string, method = 'GET') => {
    if (path.endsWith('/actions')) return []
    if (path.endsWith('/replies') && method === 'GET')
      return { items: [{ ...reply, status }], transport_configured: transport }
    if (path.endsWith('/preview')) return reply
    if (path.endsWith('/send')) return { ...reply, status: 'accepted' }
    return reply
  })
  const wrapper = mount(OperationalFollowup, {
    props: {
      caseId: 1,
      request: request as Request,
      canWrite: true,
      users: [{ id: 1, username: 'analyst', active: true, role: 'analyst' }]
    }
  })
  return { wrapper, request }
}
describe('reporter follow-up', () => {
  it('reconciles a verified failure with evidence and never resends automatically', async () => {
    const { wrapper, request } = fixture(true, 'uncertain')
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Rapprocher le résultat d’envoi')!
      .trigger('click')
    const form = wrapper.findAll('form').find((f) => f.text().includes('Résultat vérifié'))!
    const save = form.findAll('button').find((b) => b.text() === 'Enregistrer le résultat vérifié')!
    expect(save.attributes('disabled')).toBeDefined()
    await form.get('select').setValue('failed')
    await form.get('textarea').setValue('SMTP reference IR-789: rejected')
    await form.trigger('submit')
    await flushPromises()
    expect(request).toHaveBeenCalledWith('/replies/7/reconcile', 'POST', {
      revision: 1,
      outcome: 'failed',
      proof: 'SMTP reference IR-789: rejected'
    })
    expect(request.mock.calls.some(([path]) => path.endsWith('/send'))).toBe(false)
    await wrapper.setProps({ canWrite: false })
    expect(
      wrapper.findAll('button').some((b) => b.text() === 'Rapprocher le résultat d’envoi')
    ).toBe(false)
    wrapper.unmount()
  })
  it('draft preview renders message as text and never sends automatically', async () => {
    const { wrapper, request } = fixture()
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Prévisualiser')!
      .trigger('click')
    await flushPromises()
    expect(wrapper.find('.reply-preview pre').text()).toBe(reply.body)
    expect(wrapper.find('.reply-preview script').exists()).toBe(false)
    expect(request.mock.calls.some(([path]) => path.endsWith('/send'))).toBe(false)
    expect(
      wrapper
        .findAll('button')
        .find((b) => b.text() === 'Envoyer cette réponse')!
        .attributes('disabled')
    ).toBeDefined()
  })
  it('an explicitly confirmed send carries the preview revision', async () => {
    const { wrapper, request } = fixture(true)
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Prévisualiser')!
      .trigger('click')
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Envoyer cette réponse')!
      .trigger('click')
    await flushPromises()
    expect(request).toHaveBeenCalledWith('/replies/7/send', 'POST', { revision: 1 })
  })
  it('read-only users receive neither editor nor send operation', async () => {
    const { wrapper, request } = fixture(true)
    await flushPromises()
    await wrapper.setProps({ canWrite: false })
    expect(wrapper.find('form').exists()).toBe(false)
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Prévisualiser')!
      .trigger('click')
    await flushPromises()
    expect(wrapper.findAll('button').some((b) => b.text() === 'Envoyer cette réponse')).toBe(false)
    expect(request.mock.calls.some(([path]) => path.endsWith('/send'))).toBe(false)
  })
})
