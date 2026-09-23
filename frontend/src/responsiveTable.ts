import type { ObjectDirective } from 'vue'

function labelCells(table: HTMLTableElement) {
  table.classList.add('responsive-table')
  table.setAttribute('role', 'table')
  const labels = Array.from(
    table.tHead?.querySelectorAll('th') || [],
    (cell) => cell.textContent?.trim() || ''
  )
  table.querySelectorAll('tr').forEach((row) => row.setAttribute('role', 'row'))
  table.querySelectorAll('th').forEach((cell) => {
    cell.setAttribute('role', 'columnheader')
    cell.setAttribute('scope', 'col')
  })
  for (const body of table.tBodies)
    for (const row of body.rows) {
      Array.from(row.cells).forEach((cell, index) => {
        cell.dataset.label = labels[index] || ''
        cell.setAttribute('role', 'cell')
      })
    }
}
export const vResponsiveTable: ObjectDirective<HTMLTableElement> = {
  mounted: labelCells,
  updated: labelCells
}
