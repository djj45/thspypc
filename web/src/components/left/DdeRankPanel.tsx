import { useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import type { RankItem } from '../../types'
import { Cell, StateBox, StockTable, useQuoteExt, type StockRowData } from './shared'

export function DdeRankPanel() {
  const { data, loading, error } = useData<RankItem[]>(
    () => api.ddeRank(),
    [],
    'snapshot',
    1000,
  )
  const nameMap = useStockNames()
  const [visibleCodes, setVisibleCodes] = useState<string[]>([])
  const quotes = useQuoteExt(visibleCodes)

  const rows: StockRowData[] = (data ?? []).map((r) => {
    const q = quotes.get(r.code)
    // DDE 排行口径：优先 0xc4 表 dt248（亿→元归一），退回排序值×1e8
    const ddeYi = q?.dde_main ?? (typeof r.value === 'number' ? r.value : null)
    return {
      code: r.code,
      name: nameMap.get(r.code) ?? r.name ?? '',
      chgPct: q?.chg_pct ?? undefined,
      auctionChgPct: q?.auction_chg_pct ?? undefined,
      auctionAmount: q?.auction_amount ?? undefined,
      amount: q?.amount ?? undefined,
      speed4m: q?.speed_4m ?? undefined,
      mainInflow: ddeYi != null ? ddeYi * 1e8 : undefined,
    }
  })

  return (
    <Cell title="主力排行">
      <StateBox loading={loading} error={error} empty={rows.length === 0}>
        <StockTable rows={rows} onVisible={setVisibleCodes} />
      </StateBox>
    </Cell>
  )
}
