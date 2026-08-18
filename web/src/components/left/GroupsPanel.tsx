import { useMemo, useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import type { StockGroup } from '../../types'
import { isQuoteable } from './format'
import { Cell, StateBox, StockTable, useQuoteExt, type StockRowData } from './shared'

export function GroupsPanel() {
  const { data, loading, error } = useData<StockGroup[]>(() => api.groups(), [])
  const nameMap = useStockNames()
  const [selected, setSelected] = useState('')

  const groups = useMemo(
    () => (data ?? []).filter((g) => !g.is_dynamic && g.group_id !== '__selfstock__'),
    [data],
  )
  const active = groups.find((g) => g.name === selected) ?? groups[0]
  const items = useMemo(
    () => (active?.items ?? []).filter((item) => isQuoteable(item.code)),
    [active],
  )
  const [visibleCodes, setVisibleCodes] = useState<string[]>([])
  const quotes = useQuoteExt(visibleCodes)

  const rows: StockRowData[] = items.map((item) => {
    const q = quotes.get(item.code)
    return {
      code: item.code,
      name: nameMap.get(item.code) ?? '',
      chgPct: q?.chg_pct ?? undefined,
      auctionChgPct: q?.auction_chg_pct ?? undefined,
      auctionAmount: q?.auction_amount ?? undefined,
      amount: q?.amount ?? undefined,
      speed4m: q?.speed_4m ?? undefined,
      mainInflow: q?.main_inflow ?? undefined,
    }
  })

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
        empty={!active || items.length === 0}
      >
        <StockTable key={active?.group_id ?? 'none'} rows={rows} onVisible={setVisibleCodes} />
      </StateBox>
    </Cell>
  )
}
