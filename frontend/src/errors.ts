import { locale } from '@/i18n'
import { messages } from '@/i18n/messages'

type Pair = [string, string]
const generic: Pair = ['Une erreur est survenue. Réessayez.', 'Something went wrong. Please retry.']
const statuses: Record<number, Pair> = {
  400: ['La demande est invalide.', 'The request is invalid.'],
  401: ['Authentification requise. Reconnectez-vous.', 'Authentication required. Sign in again.'],
  403: ['Vous ne pouvez pas effectuer cette action.', 'You cannot perform this action.'],
  404: ['La ressource est introuvable.', 'The resource was not found.'],
  409: ['L’état a changé. Actualisez puis réessayez.', 'The state changed. Refresh and retry.'],
  410: ['Cette ressource n’est plus disponible.', 'This resource is no longer available.'],
  413: ['Le fichier dépasse la taille autorisée.', 'The file exceeds the allowed size.'],
  422: ['Vérifiez les informations saisies.', 'Check the information you entered.'],
  429: ['Trop de tentatives. Réessayez plus tard.', 'Too many attempts. Try again later.'],
  503: [
    'Le service est indisponible. Réessayez plus tard.',
    'The service is unavailable. Try again later.'
  ]
}
const known: Record<string, Pair> = {
  'Code invalide': ['Code invalide', 'Invalid code'],
  'Vérification expirée': ['Vérification expirée', 'Verification expired'],
  'Identifiants invalides': ['Identifiants invalides.', 'Invalid credentials.'],
  'Authentification requise': statuses[401]!,
  'Droits analyste requis': ['Droits analyste requis.', 'Analyst access required.'],
  'Droits administrateur requis': [
    'Droits administrateur requis.',
    'Administrator access required.'
  ],
  'En-tête de protection CSRF requis': [
    'Rechargez la page avant de réessayer.',
    'Reload the page before retrying.'
  ],
  'Identifiant déjà utilisé': [
    'Cet identifiant est déjà utilisé.',
    'This username is already in use.'
  ],
  'Formats acceptés : EML et MSG': [
    'Formats acceptés : EML et MSG.',
    'Accepted formats: EML and MSG.'
  ],
  'Fichier limité à 20 Mo': ['Le fichier est limité à 20 Mo.', 'Files are limited to 20 MB.'],
  'Fichier vide': ['Le fichier est vide.', 'The file is empty.'],
  'Invalid or expired API token': [
    'Jeton API invalide ou expiré.',
    'Invalid or expired API token.'
  ],
  'External action disabled by connectivity policy': [
    'Cette action externe est bloquée par la politique de connectivité.',
    'This external action is blocked by connectivity policy.'
  ],
  'Provider key is not configured': [
    'La clé du provider n’est pas configurée.',
    'The provider key is not configured.'
  ],
  'Target is not present in this analysis': [
    'La cible ne figure pas dans cette analyse.',
    'The target is not present in this analysis.'
  ],
  'Select an attachment from this analysis': [
    'Sélectionnez une pièce jointe de cette analyse.',
    'Select an attachment from this analysis.'
  ],
  'DKIM verification disabled by connectivity policy': [
    'La vérification DKIM est bloquée par la politique de connectivité.',
    'DKIM verification is blocked by connectivity policy.'
  ],
  'DKIM verification is still active; recovery is not available yet': [
    'La vérification DKIM est encore active. Attendez avant de la clore.',
    'DKIM verification is still active. Wait before closing it.'
  ],
  'A DKIM verification is pending; recover it explicitly if interrupted': [
    'Une vérification DKIM est en attente. Si elle est interrompue, clôturez-la explicitement.',
    'A DKIM check is pending. If interrupted, close it explicitly.'
  ],
  'Original evidence unavailable or modified': [
    'La preuve originale est indisponible ou son intégrité a changé.',
    'The original evidence is unavailable or its integrity changed.'
  ],
  'Verification evidence is no longer available': statuses[410]!,
  'Trop de tentatives. Réessayez après le délai indiqué.': statuses[429]!,
  'Benign hash lookup accepted; licence and quotas are not certified.': [
    'La recherche de test a été acceptée ; licence et quotas ne sont pas certifiés.',
    'The test lookup was accepted; licence and quotas are not certified.'
  ],
  'Quota endpoint accepted; private scan entitlement is checked on submission.': [
    'Le service de quotas répond ; le droit aux scans privés sera contrôlé lors de la soumission.',
    'The quota service responded; private scan entitlement is checked on submission.'
  ]
}
Object.assign(known, {
  'Vérification refusée : mot de passe ou code invalide.': [
    'Vérification refusée : mot de passe ou code invalide.',
    'Verification refused: invalid password or code.'
  ],
  "Le MFA n'est pas activé.": ["Le MFA n'est pas activé.", 'MFA is not enabled.'],
  'Code invalide ou déjà utilisé. Attendez le prochain code.': [
    'Code invalide ou déjà utilisé. Attendez le prochain code.',
    'Invalid or reused code. Wait for the next code.'
  ],
  'Configuration du chiffrement MFA invalide.': [
    'Configuration du chiffrement MFA invalide.',
    'MFA encryption is misconfigured. Contact your administrator.'
  ],
  'Clé MFA incorrecte. Restaurer la clé de cette installation.': [
    'Clé MFA incorrecte. Restaurer la clé de cette installation.',
    'The MFA key is incorrect. Ask your administrator to restore the key for this installation.'
  ],
  'Vérification expirée. Recommencez la connexion.': [
    'Vérification expirée. Recommencez la connexion.',
    'Verification expired. Restart sign-in.'
  ],
  'Recommencez la connexion.': ['Recommencez la connexion.', 'Restart sign-in.'],
  'Le MFA est déjà activé.': ['Le MFA est déjà activé.', 'MFA is already enabled.'],
  "Configuration expirée. Recommencez l'activation.": [
    "Configuration expirée. Recommencez l'activation.",
    'Setup expired. Restart enrollment.'
  ],
  "Code invalide. Vérifiez l'heure de votre application.": [
    "Code invalide. Vérifiez l'heure de votre application.",
    'Invalid code. Check the time in your authenticator app.'
  ],
  "Clé MFA indisponible. Contacter l'administrateur de l'installation.": [
    "Clé MFA indisponible. Contacter l'administrateur de l'installation.",
    'MFA key unavailable. Contact your installation administrator.'
  ],
  'Clé MFA indisponible.': [
    'Clé MFA indisponible.',
    'MFA key unavailable. Contact your administrator.'
  ],
  'Impossible de retirer vos propres droits administrateur': [
    'Impossible de retirer vos propres droits administrateur',
    'You cannot remove your own administrator access.'
  ],
  'Seules les analyses échouées peuvent être relancées': [
    'Seules les analyses échouées peuvent être relancées',
    'Only failed analyses can be retried.'
  ],
  'Preuve indisponible ou intégrité non vérifiée': [
    'Preuve indisponible ou intégrité non vérifiée',
    'The evidence is unavailable or its integrity could not be verified.'
  ],
  'Responsable invalide': ['Responsable invalide', 'Invalid assignee.']
})
const codes: Record<string, Pair> = {
  parser_timeout: ['Le délai d’analyse est dépassé.', 'Analysis timed out.'],
  resource_limit: ['Une limite de ressources a été atteinte.', 'A resource limit was reached.'],
  parser_rejected: [
    'Le format du message a été refusé par l’analyseur.',
    'The parser rejected the message format.'
  ],
  report_limit: [
    'Le résultat dépasse la taille autorisée.',
    'The result exceeds the allowed size.'
  ],
  evidence_unavailable: ['La preuve est indisponible.', 'The evidence is unavailable.'],
  evidence_integrity: [
    'L’intégrité de la preuve n’a pas pu être confirmée.',
    'Evidence integrity could not be confirmed.'
  ],
  storage_unavailable: ['Le stockage est indisponible.', 'Storage is unavailable.'],
  analysis_failed: ['L’analyse a échoué.', 'Analysis failed.'],
  timeout: ['Le provider n’a pas répondu à temps.', 'The provider timed out.'],
  network_error: [
    'Impossible de joindre le service. Vérifiez la connexion.',
    'Cannot reach the service. Check the connection.'
  ],
  rate_limited: [
    'La limite de requêtes du provider est atteinte. Réessayez plus tard.',
    'The provider request limit was reached. Try again later.'
  ],
  credentials_or_plan_rejected: [
    'Le provider a refusé les identifiants ou les droits de l’offre.',
    'The provider rejected the credentials or plan permissions.'
  ],
  request_rejected: ['Le provider a refusé la demande.', 'The provider rejected the request.'],
  invalid_response: ['La réponse du provider est invalide.', 'The provider response is invalid.'],
  response_too_large: [
    'La réponse du provider dépasse la limite autorisée.',
    'The provider response exceeds the allowed limit.'
  ],
  policy_disabled: [
    'Cette action est bloquée par la politique de connectivité.',
    'This action is blocked by connectivity policy.'
  ],
  provider_error: [
    'Le provider est indisponible. Réessayez plus tard.',
    'The provider is unavailable. Try again later.'
  ],
  unsupported_target: [
    'Cette cible n’est pas prise en charge par le provider.',
    'This target is not supported by the provider.'
  ],
  invalid_endpoint: [
    'La configuration du provider est invalide.',
    'The provider configuration is invalid.'
  ],
  invalid_job_id: [
    'La référence de traitement du provider est invalide.',
    'The provider job reference is invalid.'
  ],
  invalid_file_size: [
    'La taille du fichier est refusée par le provider.',
    'The provider rejected the file size.'
  ],
  visibility_mismatch: [
    'La visibilité du résultat diffère de la visibilité demandée.',
    'The result visibility differs from the requested visibility.'
  ],
  verification_interrupted: [
    'La vérification DKIM a été interrompue.',
    'DKIM verification was interrupted.'
  ]
}
function localized(pair: Pair) {
  return pair[locale.value === 'fr' ? 0 : 1]
}
function knownText(value: string) {
  if (Object.hasOwn(known, value)) return localized(known[value]!)
  const key = Object.hasOwn(messages, value)
    ? value
    : Object.keys(messages).find((key) => messages[key] === value)
  return key ? (locale.value === 'fr' ? key : messages[key]) : undefined
}
export class RequestError extends Error {
  constructor(
    detail: unknown,
    public status?: number,
    public code?: unknown
  ) {
    super(typeof detail === 'string' ? detail : '')
  }
}
/** Only catalogue text is displayed; arbitrary server/provider messages stay hidden. */
export function errorMessage(error: unknown, explicitCode?: unknown): string {
  const value =
    typeof error === 'string'
      ? { message: error }
      : error && typeof error === 'object'
        ? (error as { message?: unknown; status?: unknown; code?: unknown })
        : {}
  const message = typeof value.message === 'string' ? value.message : ''
  const prefix = /^\[([a-z][a-z0-9_]{0,63})\]/.exec(message)?.[1]
  const candidate =
    explicitCode ??
    value.code ??
    (prefix && Object.hasOwn(codes, prefix)
      ? prefix
      : Object.hasOwn(codes, message)
        ? message
        : undefined)
  const code =
    typeof candidate === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(candidate)
      ? candidate
      : undefined
  const status =
    typeof value.status === 'number' &&
    Number.isInteger(value.status) &&
    value.status >= 400 &&
    value.status <= 599
      ? value.status
      : undefined
  const text =
    code && Object.hasOwn(codes, code)
      ? localized(codes[code]!)
      : knownText(message) || localized(status && statuses[status] ? statuses[status]! : generic)
  return text + (status ? ` (HTTP ${status})` : '') + (code ? ` [${code}]` : '')
}
export function providerHealthMessage(result: {
  status?: string
  detail?: string
  summary?: string
}) {
  const detail = result.detail || result.summary || ''
  if (result.status === 'error') return errorMessage(detail)
  return (
    knownText(detail) ||
    localized(
      result.status === 'reachable'
        ? ['Le provider répond.', 'The provider is reachable.']
        : ['État du provider indisponible.', 'Provider status is unavailable.']
    )
  )
}
