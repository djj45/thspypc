import { useMemo, useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import type { StockGroup } from '../../types'
import { isQuoteable } from './format'
import { Cell, StateBox, StockTable, useQuoteExt, type StockRowData } from './shared'

export function SelfStocksPanel() {
  const { data, loading, error } = useData<StockGroup>(() => api.selfStocks(), [])
  const nameMap = useStockNames()
  const items = useMemo(
    () => (data?.items ?? []).filter((item) => isQuoteable(item.code)),
    [data],
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
    <Cell title="自选">
      <StateBox loading={loading} error={error} empty={items.length === 0}>
        <StockTable rows={rows} onVisible={setVisibleCodes} />
      </StateBox>
    </Cell>
  )
}
