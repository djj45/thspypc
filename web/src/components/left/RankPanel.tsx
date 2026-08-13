import { useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import { SORT_BY, SORT_BY_DT, type RankItem } from '../../types'
import { Cell, StateBox, StockTable, type StockRowData } from './shared'
import { clsOf, fmtAmt, fmtPct } from './format'

interface RankOption {
  key: string
  label: string
  sortBy: number
  kind: 'pct' | 'amt'
}

const OPTIONS: RankOption[] = [
  { key: 'chg', label: '涨幅', sortBy: SORT_BY.chg, kind: 'pct' },
  { key: 'speed', label: '涨速', sortBy: SORT_BY.speed, kind: 'pct' },
  { key: 'main', label: '主力', sortBy: SORT_BY.main_inflow, kind: 'amt' },
  { key: 'auction', label: '竞价额', sortBy: SORT_BY.auction_amount, kind: 'amt' },
  { key: 'seal', label: '封单额', sortBy: SORT_BY.seal, kind: 'amt' },
]

export function RankPanel() {
  const [key, setKey] = useState('chg')
  const opt = OPTIONS.find((o) => o.key === key) ?? OPTIONS[0]
  const { data, loading, error } = useData<RankItem[]>(
    () => api.stockListRanked(opt.sortBy, 200, true),
    [key],
    'snapshot',
    1000,
  )
  const nameMap = useStockNames()

  const dtField = SORT_BY_DT[opt.sortBy] ?? 'dt200'
  const rows: StockRowData[] = (data ?? []).map((r) => {
    const raw = r[dtField]
    // 排序响应里百分比类字段（涨幅 dt200 / 涨速 dt48）服务器存 ×1e8
    // （涨幅已活网验证 = 涨幅% × 1e8，比例恰好 10^8）；金额类（竞价额 dt150 /
    // 封单额 dt44 / 主力 dt250）为原始元，不缩放。
    const v =
      typeof raw === 'number'
        ? opt.kind === 'pct'
          ? raw / 1e8
          : raw
        : undefined
    return {
      code: r.code,
      name: nameMap.get(r.code) ?? r.name ?? '',
      value: opt.kind === 'amt' ? fmtAmt(v) : fmtPct(v),
      valueCls: clsOf(v),
    }
  })

  return (
    <Cell title="全市场">
      <div className="cell-toolbar">
        {OPTIONS.map((o) => (
          <span
            key={o.key}
            className={key === o.key ? 'chip active' : 'chip'}
            onClick={() => setKey(o.key)}
          >
            {o.label}
          </span>
        ))}
      </div>
      <StateBox loading={loading} error={error} empty={rows.length === 0}>
        <StockTable key={key} rows={rows} />
      </StateBox>
    </Cell>
  )
}
