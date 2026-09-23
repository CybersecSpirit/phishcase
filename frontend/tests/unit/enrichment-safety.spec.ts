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
  it('shows persisted health and tenant settings without contacting a provider', async () => {
    setLocale('en')
    const request = vi.fn(async () => ({
      mode: 'restricted',
      providers: [
        {
          ...provider,
          secret_source: 'tenant',
          last_healthcheck: {
            status: 'error',
            detail: '<img src=https://host.invalid/a>',
            checked_at: '2026-09-23T12:00:00Z'
          }
        }
      ]
    }))
    const wrapper = mount(EnrichmentResults, {
      props: { request, admin: true, settingsUrl: '/account#integrations' }
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Last error')
    expect(wrapper.text()).toContain('2026-09-23T12:00:00Z')
    expect(wrapper.text()).not.toContain('deployment environment')
    expect(wrapper.get('a').attributes('href')).toBe('/account#integrations')
    expect(wrapper.find('img').exists()).toBe(false)
    expect(request).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })
  it('renders urlscan fields and redirects inertly and pages through all enrichments', async () => {
    setLocale('en')
    const request = vi.fn(async (path: string) => {
      if (path === '/integrations') return { mode: 'restricted', providers: [provider] }
      return {
        total: 51,
        items: [
          {
            id: 'scan',
            provider: 'urlscan',
            action: 'lookup',
            status: 'available',
            target: { kind: 'url', value: 'https://evil.example/login' },
            summary: path.includes('offset=50') ? 'Older saved scan' : 'Latest saved scan',
            metadata: {
              title: '<img src=https://evil.example/a>',
              domain: 'evil.example',
              ip: '192.0.2.1',
              country: 'FR',
              score: 40,
              categories: ['phishing'],
              redirect_chain: ['https://evil.example/login', 'https://other.example/'],
              screenshot_url:
                'https://urlscan.io/screenshots/11111111-1111-1111-1111-111111111111.png'
            }
          }
        ]
      }
    })
    const wrapper = mount(EnrichmentResults, { props: { request, analysisId: 'a' } })
    await flushPromises()
    expect(wrapper.text()).toContain('Page title')
    expect(wrapper.text()).toContain('hxxps://other[.]example/')
    expect(wrapper.text()).toContain('phishing')
    expect(wrapper.find('img,iframe,script').exists()).toBe(false)
    expect(wrapper.find('a[href="https://evil.example/login"]').exists()).toBe(false)
    expect(wrapper.get('a').attributes('rel')).toBe('noopener noreferrer')
    await wrapper.findAll('.pagination button')[1]!.trigger('click')
    await flushPromises()
    expect(request).toHaveBeenCalledWith('/analyses/a/enrichments?limit=50&offset=50')
    expect(wrapper.text()).toContain('Older saved scan')
    wrapper.unmount()
  })
  it('keeps DKIM DNS inert until policy and explicit confirmation allow a request', async () => {
    setLocale('en')
    let allowed = false
    const request = vi.fn(async (path: string) =>
      path === '/integrations'
        ? {
            mode: allowed ? 'restricted' : 'offline',
            providers: [],
            dkim: { enabled: true, allowed, mode: allowed ? 'restricted' : 'offline' }
          }
        : { items: [], total: 0 }
    )
    const wrapper = mount(EnrichmentResults, {
      props: { request, analysisId: 'a', canWrite: true }
    })
    await flushPromises()
    expect(wrapper.get('.dkim-check button').attributes('disabled')).toBeDefined()
    expect(request.mock.calls.every((call) => call.length === 1)).toBe(true)
    allowed = true
    await wrapper.setProps({ analysisId: 'b' })
    await flushPromises()
    expect(wrapper.text()).toContain('configured DNS resolver')
    expect(wrapper.get('.dkim-check button').attributes('disabled')).toBeDefined()
    await wrapper.get('.dkim-check input').setValue(true)
    await wrapper.get('.dkim-check form').trigger('submit')
    await flushPromises()
    expect(request).toHaveBeenCalledWith(
      '/analyses/b/dkim',
      'POST',
      expect.objectContaining({ confirm: true, request_id: expect.any(String) })
    )
    wrapper.unmount()
  })
  it('closes interrupted DKIM explicitly while offline without polling or restarting DNS', async () => {
    setLocale('en')
    let recovered = false
    const request = vi.fn(async (path: string, method?: string) => {
      if (path === '/integrations')
        return {
          mode: 'offline',
          providers: [],
          dkim: { enabled: false, allowed: false, mode: 'offline' }
        }
      if (path === '/analyses/a/dkim/42/recover' && method === 'POST') recovered = true
      return {
        total: 1,
        items: [
          {
            id: 42,
            provider: 'dkim',
            action: 'verify',
            status: recovered ? 'unavailable' : 'pending',
            target: { kind: 'sha256', value: 'abc' },
            summary: 'Interrupted check',
            metadata: { verification: 'unavailable', reason_code: 'verification_interrupted' }
          }
        ]
      }
    })
    const wrapper = mount(EnrichmentResults, {
      props: { request, analysisId: 'a', canWrite: true }
    })
    await flushPromises()
    expect(request.mock.calls.every(([, method]) => method === undefined)).toBe(true)
    expect(wrapper.text()).not.toContain('Fetch result')
    expect(wrapper.get('.dkim-recovery button').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('contacts no DNS resolver')
    await wrapper.get('.dkim-recovery input').setValue(true)
    await wrapper.get('.dkim-recovery').trigger('submit')
    await flushPromises()
    expect(request).toHaveBeenCalledWith('/analyses/a/dkim/42/recover', 'POST', { confirm: true })
    expect(request.mock.calls.filter(([, method]) => method === 'POST')).toHaveLength(1)
    expect(wrapper.find('.dkim-recovery').exists()).toBe(false)
    expect(wrapper.text()).toContain('Unavailable')
    wrapper.unmount()
  })
  it('uses projected identity, chronological hops and related evidence without remote content', async () => {
    setLocale('en')
    const request = vi.fn(async () => ({ items: [], total: 0, page: 1, pages: 0 }))
    const result = {
      ...parsed,
      investigation: {
        identity: {
          raw_from: 'Finance <sender@example.test>',
          display_name: 'Finance',
          address: 'sender@example.test',
          domain: 'example.test',
          reply_to: [],
          return_path: [],
          anomalies: []
        },
        routing: {
          order: 'oldest_first',
          hops: [
            { from_: ['first'], by: ['middle'], date: '2026-01-01', src: 'untrusted' },
            { from_: ['middle'], by: ['last'], date: '2026-01-02', src: 'untrusted' }
          ]
        },
        urls: [
          {
            value: 'https://evil.example/login',
            domain: 'evil.example',
            display_texts: ['https://trusted.example/'],
            destination_mismatch: true,
            ioc_id: 7,
            analysis_count: 2,
            case_count: 2,
            campaigns: [{ id: 9, name: 'Related casework' }],
            enrichments: []
          }
        ],
        attachments: [
          {
            index: 0,
            filename: 'sample.doc',
            sha256: 'abc',
            ioc_id: 8,
            analysis_count: 3,
            case_count: 2,
            campaigns: [],
            enrichments: [],
            static_findings: [{ key: 'Macro', description: 'Static finding' }]
          }
        ]
      }
    }
    const wrapper = mount(InvestigationContext, { props: { request, analysisId: 'a', result } })
    await flushPromises()
    expect(wrapper.text()).toContain('Display name')
    expect(wrapper.text()).toContain('Finance')
    expect(wrapper.findAll('.timeline')[0]!.text()).toContain('first → middle')
    expect(wrapper.text()).toContain('link text and destination differ')
    expect(wrapper.text()).toContain('Static finding')
    expect(wrapper.find('a[href="/campaigns/9"]').exists()).toBe(true)
    expect(wrapper.find('img,iframe,script').exists()).toBe(false)
    wrapper.unmount()
  })
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
