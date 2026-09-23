import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import { FetchError } from '@/api'
import AnalysisIntake from '@/components/AnalysisIntake.vue'
import EnrichmentResults from '@/components/EnrichmentResults.vue'
import ErrorMessage from '@/components/ErrorMessage.vue'
import { errorMessage, providerHealthMessage, RequestError } from '@/errors'
import { setLocale } from '@/i18n'

describe('localized error boundaries', () => {
  it('hides unknown server text and retains only status and structured codes in both languages', () => {
    const error = new RequestError('Internal SQL failed: private-detail', 503, 'service_busy')
    setLocale('fr')
    expect(errorMessage(error)).toBe(
      'Le service est indisponible. Réessayez plus tard. (HTTP 503) [service_busy]'
    )
    setLocale('en')
    expect(errorMessage(error)).toBe(
      'The service is unavailable. Try again later. (HTTP 503) [service_busy]'
    )
    expect(errorMessage(new Error('private-detail'))).toBe('Something went wrong. Please retry.')
    expect(errorMessage(new RequestError(null, 422, '<unsafe>'))).toBe(
      'Check the information you entered. (HTTP 422)'
    )
  })
  it('keeps known credentials, MFA and DKIM guidance actionable', () => {
    setLocale('en')
    expect(errorMessage(new RequestError('Identifiants invalides', 401))).toBe(
      'Invalid credentials. (HTTP 401)'
    )
    expect(errorMessage('Code invalide ou déjà utilisé. Attendez le prochain code.')).toContain(
      'Wait for the next code'
    )
    setLocale('fr')
    expect(
      errorMessage(
        new RequestError('DKIM verification is still active; recovery is not available yet', 409)
      )
    ).toContain('Attendez avant de la clore')
  })
  it('explains stable analysis failures without revealing the original backend text', () => {
    setLocale('en')
    expect(errorMessage('[parser_timeout] private subprocess text')).toBe(
      'Analysis timed out. [parser_timeout]'
    )
    setLocale('fr')
    expect(errorMessage('private subprocess text', 'evidence_integrity')).toBe(
      'L’intégrité de la preuve n’a pas pu être confirmée. [evidence_integrity]'
    )
  })
  it('localizes provider health codes and suppresses unknown provider details', () => {
    setLocale('fr')
    expect(
      providerHealthMessage({ status: 'error', detail: 'credentials_or_plan_rejected' })
    ).toContain('identifiants ou les droits')
    expect(providerHealthMessage({ status: 'error', detail: 'private provider detail' })).toBe(
      'Une erreur est survenue. Réessayez.'
    )
    expect(
      providerHealthMessage({ status: 'reachable', detail: 'unrecognized English copy' })
    ).toBe('Le provider répond.')
    setLocale('en')
    expect(providerHealthMessage({ status: 'error', detail: 'rate_limited' })).toContain(
      'Try again later'
    )
  })
  it('protects both active request alerts and the legacy error component', async () => {
    setLocale('fr')
    const wrapper = mount(EnrichmentResults, {
      props: {
        request: async () => {
          throw new RequestError('private backend detail', 500)
        }
      }
    })
    await flushPromises()
    expect(wrapper.get('[role=alert]').text()).toBe(
      'Une erreur est survenue. Réessayez. (HTTP 500)'
    )
    wrapper.unmount()
    const legacy = mount(ErrorMessage, {
      props: {
        error: new FetchError('private status', { detail: [{ msg: 'private validation' }] }, 422)
      }
    })
    expect(legacy.text()).toBe('Vérifiez les informations saisies. (HTTP 422)')
    legacy.unmount()
  })
  it('shows a localized terminal upload failure instead of raw server text', async () => {
    setLocale('en')
    const wrapper = mount(AnalysisIntake, {
      props: {
        canUpload: true,
        uploadFile: async () => ({
          id: 'a',
          case_id: 1,
          subject: '',
          filename: 'synthetic.eml',
          status: 'failed',
          error: 'private parser text',
          error_code: 'parser_rejected'
        }),
        getAnalysis: async () => {
          throw new Error('unused')
        }
      }
    })
    const input = wrapper.get('input[type=file]')
    Object.defineProperty(input.element, 'files', {
      value: [new File(['synthetic'], 'synthetic.eml')]
    })
    await input.trigger('change')
    await flushPromises()
    expect(wrapper.text()).toContain('The parser rejected the message format. [parser_rejected]')
    expect(wrapper.text()).not.toContain('private parser text')
    wrapper.unmount()
  })
})
