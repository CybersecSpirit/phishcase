import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import WorkspaceView from '@/views/WorkspaceView.vue'

function reply(body: unknown, status = 200) {
  return { ok: status < 400, status, json: async () => body }
}

afterEach(() => vi.unstubAllGlobals())

describe('MFA login', () => {
  it('does not load workspace data until the second factor is accepted', async () => {
    const fetch = vi.fn(async (url: string) => {
      if (url.endsWith('/auth/me')) return reply({ detail: 'Authentification requise' }, 401)
      if (url.endsWith('/auth/login')) return reply({ mfa_required: true })
      if (url.endsWith('/auth/mfa/verify'))
        return reply({ id: 1, username: 'analyst', role: 'analyst' })
      if (url.endsWith('/dashboard'))
        return reply({
          cases: 0,
          open_cases: 0,
          analyses: 0,
          iocs: 0,
          failed_analyses: 0,
          activity: []
        })
      return reply([])
    })
    vi.stubGlobal('fetch', fetch)
    const wrapper = mount(WorkspaceView, { global: { stubs: { AnalysisIntake: true } } })
    await flushPromises()
    await wrapper.get('input[autocomplete=username]').setValue('analyst')
    await wrapper.get('input[type=password]').setValue('password-example')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('Vérification en deux étapes')
    expect(wrapper.find('.workspace').exists()).toBe(false)
    expect(fetch.mock.calls.some(([url]) => url.endsWith('/dashboard'))).toBe(false)
    await wrapper.get('input[autocomplete=one-time-code]').setValue('123456')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.find('.workspace').exists()).toBe(true)
    expect(wrapper.text()).toContain('Mon compte')
    expect(fetch.mock.calls.some(([url]) => url.endsWith('/dashboard'))).toBe(true)
    wrapper.unmount()
  })

  it('supports recovery codes and returns to password login when the challenge expires', async () => {
    const fetch = vi.fn(async (url: string) => {
      if (url.endsWith('/auth/login')) return reply({ mfa_required: true })
      return reply({ detail: 'Vérification expirée' }, 401)
    })
    vi.stubGlobal('fetch', fetch)
    const wrapper = mount(WorkspaceView)
    await flushPromises()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Utiliser un code de récupération')!
      .trigger('click')
    expect(wrapper.text()).toContain('Code de récupération')
    await wrapper.get('input[autocomplete=one-time-code]').setValue('test-recovery-code')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.find('input[type=password]').exists()).toBe(true)
    expect(wrapper.get('[role=alert]').text()).toBe('Vérification expirée')
    expect(wrapper.find('.workspace').exists()).toBe(false)
    wrapper.unmount()
  })
})
