import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import ActionMenu from '@/components/ActionMenu.vue'

describe('secondary action disclosure', () => {
  it('closes on selection, Escape and outside interaction without losing keyboard focus', async () => {
    const wrapper = mount(ActionMenu, {
      attachTo: document.body,
      slots: { default: '<button>Export</button>' }
    })
    const details = wrapper.get('details').element as HTMLDetailsElement
    details.open = true
    await wrapper.get('button').trigger('click')
    expect(details.open).toBe(false)
    expect(document.activeElement).toBe(wrapper.get('summary').element)
    details.open = true
    await wrapper.trigger('keydown', { key: 'Escape' })
    expect(details.open).toBe(false)
    details.open = true
    document.body.dispatchEvent(new Event('pointerdown', { bubbles: true }))
    expect(details.open).toBe(false)
    wrapper.unmount()
  })
})
