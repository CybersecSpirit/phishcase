import { flushPromises, mount } from '@vue/test-utils'
import { expect, it, vi } from 'vitest'

import CampaignWorkspace from '@/components/CampaignWorkspace.vue'
import router from '@/router'

it('rehydrates campaign filters from direct URLs and route changes', async () => {
  await router.replace('/campaigns?q=invoice&page=2')
  const request = vi.fn(async () => ({ items: [], total: 51, page: 2, page_size: 50, pages: 2 }))
  const wrapper = mount(CampaignWorkspace, { props: { request, canWrite: false } })
  await flushPromises()
  expect(request.mock.calls[0]![0]).toContain('q=invoice')
  expect(request.mock.calls[0]![0]).toContain('page=2')
  expect(wrapper.find('input').element.value).toBe('invoice')
  await router.replace('/campaigns?q=credential&page=1')
  await flushPromises()
  expect(wrapper.find('input').element.value).toBe('credential')
  expect(request.mock.calls.at(-1)![0]).toContain('q=credential')
  wrapper.unmount()
})
