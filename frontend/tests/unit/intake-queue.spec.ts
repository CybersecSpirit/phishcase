import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import AnalysisIntake from '@/components/AnalysisIntake.vue'
import { setLocale } from '@/i18n'
afterEach(() => vi.useRealTimers())
describe('durable asynchronous uploads', () => {
  it('accepts a queued upload and polls until completion without reporting an upload failure', async () => {
    vi.useFakeTimers()
    setLocale('en')
    const queued = {
      id: 'job-1',
      case_id: 42,
      filename: 'sample.eml',
      subject: 'Queued evidence',
      status: 'queued'
    }
    const uploadFile = vi.fn().mockResolvedValue(queued),
      getAnalysis = vi
        .fn()
        .mockResolvedValueOnce({ ...queued, status: 'running' })
        .mockResolvedValueOnce({ ...queued, status: 'completed' })
    const wrapper = mount(AnalysisIntake, { props: { canUpload: true, uploadFile, getAnalysis } })
    const input = wrapper.get('input[type=file]')
    Object.defineProperty(input.element, 'files', {
      value: [new File(['test'], 'sample.eml')],
      configurable: true
    })
    await input.trigger('change')
    await flushPromises()
    expect(wrapper.text()).toContain('Queued')
    expect(wrapper.text()).not.toContain('Analysis failed')
    expect(input.attributes('disabled')).toBeUndefined()
    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()
    expect(wrapper.text()).toContain('Analysis running')
    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()
    expect(wrapper.text()).toContain('Result available')
    expect(getAnalysis).toHaveBeenCalledTimes(2)
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(9000)
    expect(getAnalysis).toHaveBeenCalledTimes(2)
  })
  it('does not mark a queued server job failed after a temporary polling error', async () => {
    vi.useFakeTimers()
    setLocale('en')
    const queued = {
      id: 'job-1',
      case_id: 1,
      filename: 'sample.eml',
      subject: 'Stored evidence',
      status: 'queued'
    }
    const wrapper = mount(AnalysisIntake, {
      props: {
        canUpload: true,
        uploadFile: async () => queued,
        getAnalysis: vi.fn().mockRejectedValue(new Error('Network offline'))
      }
    })
    const input = wrapper.get('input[type=file]')
    Object.defineProperty(input.element, 'files', { value: [new File(['test'], 'sample.eml')] })
    await input.trigger('change')
    await flushPromises()
    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()
    expect(wrapper.text()).toContain('Queued')
    expect(wrapper.text()).not.toContain('Analysis failed')
    wrapper.unmount()
  })
})
