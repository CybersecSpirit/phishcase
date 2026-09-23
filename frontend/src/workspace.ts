export type Request = <T>(path: string, method?: string, data?: unknown) => Promise<T>
export type Page<T> = { items: T[]; total: number; page: number; page_size: number; pages: number }
export function emptyPage<T>(): Page<T> {
  return { items: [], total: 0, page: 1, page_size: 50, pages: 0 }
}
export function defang(value: string): string {
  return value
    .replace(/https?:\/\//gi, (scheme) =>
      scheme.toLowerCase() === 'https://' ? 'hxxps://' : 'hxxp://'
    )
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]')
}
export function pageQuery(
  page = 1,
  filters: Record<string, string | number | undefined> = {}
): string {
  const params = new URLSearchParams({ page: String(page), page_size: '50' })
  for (const [key, value] of Object.entries(filters))
    if (value !== undefined && value !== '') params.set(key, String(value))
  return params.toString()
}

export const eventMessages: Record<string, string> = {
  'case.created': 'Dossier créé',
  'case.updated': 'Dossier mis à jour',
  'note.added': 'Note ajoutée',
  'analysis.queued': 'Analyse en attente',
  'analysis.started': 'Analyse démarrée',
  'analysis.completed': 'Analyse terminée',
  'analysis.failed': 'Échec de l’analyse',
  'analysis.retried': 'Analyse relancée',
  'analysis.decided': 'Décision enregistrée',
  'analysis.reopened': 'Investigation rouverte',
  'campaign.created': 'Campagne créée',
  'campaign.updated': 'Campagne mise à jour',
  'campaign.deleted': 'Campagne supprimée',
  'campaign.case_attached': 'Dossier rattaché',
  'campaign.case_detached': 'Dossier détaché',
  'ioc.reviewed': 'Indicateur qualifié',
  'user.created': 'Compte créé',
  'user.updated': 'Compte mis à jour'
}
