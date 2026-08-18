import { useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import { SORT_BY, type RankItem } from '../../types'
import {
  Cell,
  StateBox,
  StockTable,
  useQuoteExt,
  type ColSort,
  type StockRowData,
} from './shared'

// 表头排序键 → 服务端 SortBy。成交额无服务端排序键（客户端走推送本地排），
// 在 StockTable disabledSortKeys 里禁用。
const SERVER_SORT: Record<string, number> = {
  chgPct: SORT_BY.chg,
  speed4m: SORT_BY.speed,
  mainInflow: SORT_BY.main_inflow,
  auctionAmount: SORT_BY.auction_amount,
  auctionChgPct: SORT_BY.auction_chg,
  sealAmount: SORT_BY.seal,
}

// 全市场榜一次拉全（L2 账号走 SortCount 放大单请求，约 0.1s），
// 列表用滚轮虚拟滚动，数值列按可视窗口增量取。
const FULL_MARKET_COUNT = 5400

export function RankPanel() {
  const [sort, setSort] = useState<ColSort>({ key: 'chgPct', desc: true })
  const sortBy = SERVER_SORT[sort.key] ?? SORT_BY.chg
  const { data, loading, error } = useData<RankItem[]>(
    () =>
      api.stockListRanked(
        sortBy,
        FULL_MARKET_COUNT,
        true,
        sort.desc ? 'D' : 'A',
      ),
    [sortBy, sort.desc],
    'snapshot',
    1000,
  )
  const nameMap = useStockNames()
  const [visibleCodes, setVisibleCodes] = useState<string[]>([])
  const quotes = useQuoteExt(visibleCodes)

  const rows: StockRowData[] = (data ?? []).map((r) => {
    const q = quotes.get(r.code)
    const row: StockRowData = {
      code: r.code,
      name: nameMap.get(r.code) ?? r.name ?? '',
      chgPct: r.dt200 ?? q?.chg_pct ?? undefined,
      auctionChgPct: q?.auction_chg_pct ?? undefined,
      auctionAmount: q?.auction_amount ?? undefined,
      amount: q?.amount ?? undefined,
      speed4m: r.dt48 ?? q?.speed_4m ?? undefined,
      // 主力净额直查 0xc4 金额表（元）；排序响应的 dt250 今日不可靠
      mainInflow: q?.main_inflow ?? undefined,
    }
    // 排序值本身就是该列的真值（服务端排序口径），有值时优先。
    // 主力列例外：592890 排序响应今日回 dt44（封单额），不再采信 r.value。
    const v = typeof r.value === 'number' ? r.value : undefined
    if (v !== undefined) {
      if (sort.key === 'chgPct') row.chgPct = v
      else if (sort.key === 'speed4m') row.speed4m = v
      else if (sort.key === 'auctionAmount') row.auctionAmount = v
      else if (sort.key === 'auctionChgPct') row.auctionChgPct = v
      else if (sort.key === 'sealAmount') row.sealAmount = v
    }
    return row
  })

  return (
    <Cell title="全市场">
      <StateBox loading={loading} error={error} empty={rows.length === 0}>
        <StockTable
          key={`${sort.key}-${sort.desc}`}
          rows={rows}
          onVisible={setVisibleCodes}
          sort={sort}
          onSortChange={setSort}
          disabledSortKeys={['amount']}
        />
      </StateBox>
    </Cell>
  )
}
