import { useMemo, useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import { isQuoteable } from './format'
import { Cell, StateBox, StockTable, useQuoteExt, type StockRowData } from './shared'

export function DynamicPlatesPanel() {
  const { data, loading, error } = useData<Record<string, string[]>>(
    () => api.dynamicPlates(),
    [],
  )
  const nameMap = useStockNames()
  const [selected, setSelected] = useState('')

  const names = useMemo(() => Object.keys(data ?? {}), [data])
  const active = names.includes(selected) ? selected : names[0]
  const codes = useMemo(
    () =>
      (data?.[active] ?? [])
        .filter((full) => isQuoteable(full.split('.')[0]))
        .map((full) => full.split('.')[0]),
    [data, active],
  )
  const [visibleCodes, setVisibleCodes] = useState<string[]>([])
  const quotes = useQuoteExt(visibleCodes)

  const rows: StockRowData[] = codes.map((code) => {
    const q = quotes.get(code)
    return {
      code,
      name: nameMap.get(code) ?? '',
      chgPct: q?.chg_pct ?? undefined,
      auctionChgPct: q?.auction_chg_pct ?? undefined,
      auctionAmount: q?.auction_amount ?? undefined,
      amount: q?.amount ?? undefined,
      speed4m: q?.speed_4m ?? undefined,
      mainInflow: q?.main_inflow ?? undefined,
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
        <StockTable key={active ?? 'none'} rows={rows} onVisible={setVisibleCodes} />
      </StateBox>
    </Cell>
  )
}
