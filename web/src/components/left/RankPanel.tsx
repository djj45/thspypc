import { useEffect, useMemo, useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import { useStock } from '../../state/StockContext'
import { SORT_BY, type RankItem } from '../../types'
import {
  Cell,
  StateBox,
  StockTable,
  useQuoteExt,
  type ColSort,
  type StockRowData,
} from './shared'

// 表头排序键 → 服务端 SortBy（全部活网验证；19=成交额/13=成交量 为
// 2026-08-19 L2 排序路径新验证，此前文档误以为成交额不可排）。
const SERVER_SORT: Record<string, number> = {
  chgPct: SORT_BY.chg,
  speed4m: SORT_BY.speed,
  mainInflow: SORT_BY.main_inflow,
  auctionAmount: SORT_BY.auction_amount,
  auctionChgPct: SORT_BY.auction_chg,
  sealAmount: SORT_BY.seal,
  amount: SORT_BY.amount,
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
  const { globalCodesRef } = useStock()
  const [visibleCodes, setVisibleCodes] = useState<string[]>([])
  const quotes = useQuoteExt(visibleCodes)

  // 全市场代码（升序）注册给全局切换：未点过任何列表时，方向键/滚轮按代码
  // 递增递减切换（首尾循环）。
  useEffect(() => {
    if (data?.length) {
      globalCodesRef.current = data
        .map((r) => r.code)
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    }
  }, [data, globalCodesRef])

  // 快速切股时 code 每秒变数十次，此处 5400 行映射必须 memo，避免每帧重建
  const rows: StockRowData[] = useMemo(() => {
    return (data ?? []).map((r) => {
    const q = quotes.get(r.code)
    const row: StockRowData = {
      code: r.code,
      name: nameMap.get(r.code) ?? r.name ?? '',
      chgPct: r.dt200 ?? q?.chg_pct ?? undefined,
      auctionChgPct: r.dt154 ?? q?.auction_chg_pct ?? undefined,
      // 排序榜自身的字段已经由后端按独立行情真值校准；排序列必须优先
      // 显示同一口径，不能再被稍后返回的可视区行情造成“顺序和值不符”。
      auctionAmount: r.auction_amount ?? q?.auction_amount ?? undefined,
      amount: r.dt19 ?? q?.amount ?? undefined,
      speed4m: r.dt48 ?? q?.speed_4m ?? undefined,
      // 主力净额：0xc4 直查优先，排序响应 dt250 即时填充（后端有漂移守卫）
      mainInflow: q?.main_inflow ?? r.dt250 ?? undefined,
      // 封单额：排序时由排序值覆盖，平时走 265260 排序榜缓存
      sealAmount: (r.dt44 ?? q?.seal_amount) || undefined,
    }
    // 排序值本身就是该列的真值（服务端排序口径），有值时优先。
    // 主力列例外：592890 排序响应今日回 dt44（封单额），不再采信 r.value。
    const v = typeof r.value === 'number' ? r.value : undefined
    if (v !== undefined) {
      if (sort.key === 'chgPct') row.chgPct = v
      else if (sort.key === 'speed4m') row.speed4m = v
      else if (sort.key === 'auctionAmount') row.auctionAmount = v
      else if (sort.key === 'auctionChgPct') row.auctionChgPct = v
      else if (sort.key === 'sealAmount') row.sealAmount = v || undefined
      else if (sort.key === 'amount') row.amount = v
    }
    return row
    })
  }, [data, quotes, nameMap, sort.key])

  return (
    <Cell title="全市场">
      <StateBox loading={loading} error={error} empty={rows.length === 0}>
        <StockTable
          key={`${sort.key}-${sort.desc}`}
          rows={rows}
          onVisible={setVisibleCodes}
          sort={sort}
          onSortChange={setSort}
        />
      </StateBox>
    </Cell>
  )
}
