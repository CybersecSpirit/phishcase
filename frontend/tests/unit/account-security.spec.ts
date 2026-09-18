import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import AccountSecurity from '@/components/AccountSecurity.vue'

describe('Account security', () => {
  it('requires enrollment confirmation then shows recovery codes once', async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce({ enabled: false, recovery_remaining: 0 })
      .mockResolvedValueOnce({ secret: 'TEST-SECRET', qr: 'data:image/svg+xml;base64,PHN2Zy8+' })
      .mockResolvedValueOnce({ recovery_codes: ['test-recovery-code'] })
      .mockResolvedValueOnce({ enabled: true, recovery_remaining: 10 })
    const wrapper = mount(AccountSecurity, { props: { request } })
    await flushPromises()
    await wrapper.get('input[type=password]').setValue('password-example')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(request).toHaveBeenLastCalledWith('/auth/mfa/setup', 'POST', {
      password: 'password-example'
    })
    expect(wrapper.find('img').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('test-recovery-code')
    await wrapper.get('input[autocomplete=one-time-code]').setValue('123456')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(request).toHaveBeenCalledWith('/auth/mfa/enable', 'POST', { code: '123456' })
    expect(wrapper.find('img').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('TEST-SECRET')
    expect(wrapper.text()).toContain('test-recovery-code')
    expect(wrapper.get('button.primary').attributes('disabled')).toBeDefined()
    await wrapper.get('input[type=checkbox]').setValue(true)
    await wrapper.get('button.primary').trigger('click')
    expect(wrapper.text()).not.toContain('test-recovery-code')
    expect(wrapper.text()).toContain('10 codes de récupération disponibles')
    wrapper.unmount()
  })

  it('keeps enrollment open when the first code is invalid', async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce({ enabled: false, recovery_remaining: 0 })
      .mockResolvedValueOnce({ secret: 'TEST', qr: 'data:image/svg+xml;base64,PHN2Zy8+' })
      .mockRejectedValueOnce(new Error('Code invalide'))
    const wrapper = mount(AccountSecurity, { props: { request } })
    await flushPromises()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role=alert]').text()).toBe('Code invalide')
    expect(wrapper.find('img').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('Conservez vos codes')
    wrapper.unmount()
  })

  it('requires a password and second factor to disable MFA', async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce({ enabled: true, recovery_remaining: 9 })
      .mockResolvedValueOnce({ ok: true })
      .mockResolvedValueOnce({ enabled: false, recovery_remaining: 0 })
    const wrapper = mount(AccountSecurity, { props: { request } })
    await flushPromises()
    await wrapper
      .findAll('button')
      .find((b) => b.text() === 'Désactiver le MFA')!
      .trigger('click')
    await wrapper.get('input[type=password]').setValue('password-example')
    await wrapper.get('input[autocomplete=one-time-code]').setValue('test-recovery-code')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(request).toHaveBeenCalledWith('/auth/mfa/disable', 'POST', {
      password: 'password-example',
      code: 'test-recovery-code'
    })
    expect(wrapper.text()).toContain('Le MFA est désactivé')
    expect(wrapper.text()).toContain('Configurer le MFA')
    wrapper.unmount()
  })
})
