import { useMemo, useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import { isQuoteable } from './format'
import { Cell, StateBox, StockTable, type StockRowData } from './shared'

export function DynamicPlatesPanel() {
  const { data, loading, error } = useData<Record<string, string[]>>(
    () => api.dynamicPlates(),
    [],
  )
  const nameMap = useStockNames()
  const [selected, setSelected] = useState('')

  const names = useMemo(() => Object.keys(data ?? {}), [data])
  const active = names.includes(selected) ? selected : names[0]

  const rows: StockRowData[] = (data?.[active] ?? [])
    .filter((full) => isQuoteable(full.split('.')[0]))
    .map((full) => {
      const code = full.split('.')[0]
      const market = full.split('.')[1] ?? ''
      return {
        code,
        name: nameMap.get(code) ?? '',
        value: market,
        valueCls: 'dim',
      }
    })

  return (
    <Cell title="动态板块">
      <div className="cell-toolbar">
        <select value={active ?? ''} onChange={(e) => setSelected(e.target.value)}>
          {names.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </div>
      <StateBox loading={loading} error={error} empty={names.length === 0}>
        <StockTable key={active ?? 'none'} rows={rows} />
      </StateBox>
    </Cell>
  )
}
