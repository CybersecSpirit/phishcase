import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { setLocale } from '@/i18n'
import router from '@/router'
import WorkspaceView from '@/views/WorkspaceView.vue'
const page = (items: unknown[], total = items.length, current = 1) => ({
  items,
  total,
  page: current,
  page_size: 50,
  pages: Math.ceil(total / 50)
})
const reply = (body: unknown) => ({ ok: true, status: 200, json: async () => body })
const oldAnalysis = {
  id: 'old-analysis',
  case_id: 42,
  filename: 'old.eml',
  subject: 'Evidence older than 500 global emails',
  status: 'completed',
  sha256: 'abc',
  created_at: '2024-01-01T00:00:00Z'
}
function stubApi(
  analysis: typeof oldAnalysis & { result?: Record<string, unknown> } = oldAnalysis
) {
  const fetch = vi.fn(async (input: string) => {
    const url = new URL(input, 'http://localhost')
    if (url.pathname.endsWith('/auth/me'))
      return reply({ id: 1, username: 'analyst', role: 'analyst' })
    if (url.pathname.endsWith('/auth/preferences')) return reply({ locale: 'fr' })
    if (url.pathname.endsWith('/dashboard'))
      return reply({
        cases: 2,
        open_cases: 1,
        analyses: 601,
        iocs: 1,
        failed_analyses: 0,
        activity: [],
        pending_verdicts: 12,
        active_campaigns: 4,
        recent_analyses: [oldAnalysis],
        frequent_iocs: [
          { id: 7, kind: 'url', value: 'https://evil.example', analysis_count: 8, case_count: 3 }
        ]
      })
    if (url.pathname.endsWith('/users')) return reply([])
    if (url.pathname.endsWith('/integrations')) return reply({ mode: 'offline', providers: [] })
    if (url.pathname.endsWith('/cases/42/events')) return reply(page([]))
    if (url.pathname.endsWith('/cases/42'))
      return reply({
        id: 42,
        title: 'Older case',
        description: '',
        status: 'open',
        priority: 'medium',
        assignee_id: null,
        notes: []
      })
    if (url.pathname.endsWith('/cases'))
      return reply(
        page(
          [{ id: 42, title: 'Older case', status: 'open', priority: 'medium', analysis_count: 1 }],
          1
        )
      )
    if (url.pathname.endsWith('/analyses/old-analysis')) return reply(analysis)
    if (url.pathname.endsWith('/analyses'))
      return reply(
        page(
          url.searchParams.get('case_id') === '42'
            ? [oldAnalysis]
            : [{ ...oldAnalysis, id: 'recent', subject: 'Recent analysis' }],
          url.searchParams.has('case_id') ? 1 : 601,
          Number(url.searchParams.get('page') || 1)
        )
      )
    if (url.pathname.endsWith('/iocs/7'))
      return reply({
        id: 7,
        kind: 'url',
        value: 'https://evil.example',
        verdict: 'unreviewed',
        analysis_count: 1,
        case_count: 1
      })
    if (url.pathname.endsWith('/iocs/7/occurrences'))
      return reply(
        page([{ id: 'old-analysis', case_id: 42, filename: 'old.eml', title: 'Older case' }])
      )
    if (url.pathname.endsWith('/iocs')) return reply(page([]))
    return reply(page([]))
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}
beforeEach(async () => {
  setLocale('fr')
  localStorage.setItem('phishcase.locale.1', 'fr')
  await router.replace('/')
})
afterEach(() => vi.unstubAllGlobals())
const options = {
  global: { stubs: { AnalysisIntake: true, AnalystDecision: true, InvestigationContext: true } }
}
describe('shareable workspace navigation and pagination', () => {
  it('opens the mobile disclosure and closes it on navigation or Escape', async () => {
    stubApi()
    const wrapper = mount(WorkspaceView, { ...options, attachTo: document.body })
    await flushPromises()
    const menu = wrapper.get('.mobile-menu-button')
    expect(menu.attributes('aria-expanded')).toBe('false')
    await menu.trigger('click')
    expect(menu.attributes('aria-expanded')).toBe('true')
    expect(wrapper.get('#workspace-navigation').classes()).toContain('is-open')
    const overview = wrapper
      .findAll('.sidebar nav button')
      .find((node) => node.text().includes('Vue d’ensemble'))
    expect(overview).toBeDefined()
    await overview!.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/dashboard')
    expect(menu.attributes('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(menu.element)
    await menu.trigger('click')
    await wrapper.get('.sidebar').trigger('keydown', { key: 'Escape' })
    expect(menu.attributes('aria-expanded')).toBe('false')
    wrapper.unmount()
  })

  it('shows actionable dashboard work and keeps frequent indicators inert', async () => {
    stubApi()
    await router.replace('/dashboard')
    const wrapper = mount(WorkspaceView, options)
    await flushPromises()
    expect(wrapper.text()).toContain('Verdicts en attente')
    expect(wrapper.text()).toContain('Campagnes actives')
    expect(wrapper.text()).toContain(oldAnalysis.subject)
    expect(wrapper.find('a[href="/analyses/old-analysis"]').exists()).toBe(true)
    expect(wrapper.find('a[href="/iocs/7"]').exists()).toBe(true)
    expect(wrapper.find('a[href="https://evil.example"]').exists()).toBe(false)
    wrapper.unmount()
  })
  it('uses the text projection and exports only explicitly selected attachments', async () => {
    stubApi({
      ...oldAnalysis,
      result: {
        eml: {
          header: { from_: 'sender@example.test', to: [], date: '' },
          bodies: [
            {
              content_type: 'text/html',
              content: '<img src="https://evil.example/a"><b>Readable text</b>'
            }
          ],
          attachments: [0, 1].map((index) => ({
            filename: `attachment-${index}.txt`,
            size: 1,
            mime_type: 'text/plain',
            hash: { sha256: 'abc' }
          }))
        },
        verdicts: [],
        investigation: { bodies: [{ index: 0, content_type: 'text/html', text: 'Readable text' }] }
      }
    })
    await router.replace('/analyses/old-analysis')
    const wrapper = mount(WorkspaceView, options)
    await flushPromises()
    const archive = () => wrapper.get('a[href*="/evidence.zip"]')
    expect(archive().attributes('href')).toBe(
      '/api/workspace/analyses/old-analysis/evidence.zip?attachments='
    )
    await wrapper.findAll('.email-report input[type=checkbox]')[1]!.setValue(true)
    expect(archive().attributes('href')).toBe(
      '/api/workspace/analyses/old-analysis/evidence.zip?attachments=1'
    )
    expect(wrapper.find('.email-report').text()).toContain('Readable text')
    expect(wrapper.find('.email-report').text()).not.toContain('<img')
    expect(wrapper.find('.email-report img').exists()).toBe(false)
    wrapper.unmount()
  })
  it('hydrates an old case from its URL and requests its analyses independently of the global list', async () => {
    const fetch = stubApi()
    await router.replace('/cases/42')
    const wrapper = mount(WorkspaceView, options)
    await flushPromises()
    expect(wrapper.text()).toContain(oldAnalysis.subject)
    expect(
      fetch.mock.calls.some(
        ([url]) =>
          url.includes('/analyses?') && url.includes('case_id=42') && url.includes('page_size=50')
      )
    ).toBe(true)
    expect(
      fetch.mock.calls.some(([url]) => url.includes('/analyses?') && !url.includes('case_id=42'))
    ).toBe(false)
    wrapper.unmount()
  })
  it('keeps analysis pages in the URL and restores them on back and forward', async () => {
    const fetch = stubApi()
    await router.replace('/analyses?page=2')
    const wrapper = mount(WorkspaceView, options)
    await flushPromises()
    expect(wrapper.text()).toContain('601 résultats · page 2 sur 13')
    await wrapper
      .findAll('.pagination button')
      .find((b) => b.text() === 'Suivant')!
      .trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query.page).toBe('3')
    router.back()
    await new Promise((resolve) => setTimeout(resolve, 30))
    await flushPromises()
    expect(router.currentRoute.value.query.page).toBe('2')
    expect(wrapper.text()).toContain('page 2 sur 13')
    router.forward()
    await new Promise((resolve) => setTimeout(resolve, 30))
    await flushPromises()
    expect(wrapper.text()).toContain('page 3 sur 13')
    expect(fetch.mock.calls.some(([url]) => url.includes('page=3'))).toBe(true)
    wrapper.unmount()
  })
  it('opens analysis and IOC details directly without requiring a list selection', async () => {
    stubApi()
    await router.replace('/analyses/old-analysis')
    const wrapper = mount(WorkspaceView, options)
    await flushPromises()
    expect(wrapper.find('.report').text()).toContain(oldAnalysis.subject)
    await router.push('/iocs/7')
    await flushPromises()
    expect(wrapper.text()).toContain('hxxps://evil[.]example')
    expect(wrapper.find('a[href="https://evil.example"]').exists()).toBe(false)
    wrapper.unmount()
  })
})
