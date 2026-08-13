import { useMemo, useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import type { StockGroup } from '../../types'
import { fmtNum, isQuoteable } from './format'
import { Cell, StateBox, StockTable, type StockRowData } from './shared'

export function GroupsPanel() {
  const { data, loading, error } = useData<StockGroup[]>(() => api.groups(), [])
  const nameMap = useStockNames()
  const [selected, setSelected] = useState('')

  const groups = useMemo(
    () => (data ?? []).filter((g) => !g.is_dynamic && g.group_id !== '__selfstock__'),
    [data],
  )
  const active = groups.find((g) => g.name === selected) ?? groups[0]

  const rows: StockRowData[] = (active?.items ?? [])
    .filter((item) => isQuoteable(item.code))
    .map((item) => ({
      code: item.code,
      name: nameMap.get(item.code) ?? '',
      value: fmtNum(item.price),
      valueCls: 'flat',
    }))

  return (
    <Cell title="自定义板块">
      <div className="cell-toolbar">
        <select value={active?.name ?? ''} onChange={(e) => setSelected(e.target.value)}>
          {groups.map((g) => (
            <option key={g.group_id} value={g.name}>
              {g.name}
            </option>
          ))}
        </select>
      </div>
      <StateBox
        loading={loading}
        error={error}
        empty={!active || active.items.length === 0}
      >
        <StockTable key={active?.group_id ?? 'none'} rows={rows} />
      </StateBox>
    </Cell>
  )
}
