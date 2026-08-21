import { useStock } from '../../state/StockContext'
import type { MarketEvent } from '../../types'

function cls(v: number | undefined) {
  if (v === undefined) return 'flat'
  if (v > 0) return 'up'
  if (v < 0) return 'down'
  return 'flat'
}
function fmt(n: number | undefined, digits = 2) {
  return n == null ? '--' : n.toFixed(digits)
}
function fmtVol(n: number | undefined) {
  if (n == null) return '--'
  if (n >= 1e8) return (n / 1e8).toFixed(2) + '亿'
  if (n >= 1e4) return (n / 1e4).toFixed(1) + '万'
  return n.toFixed(0)
}

// 盘口上方的股票信息条（参考同花顺盘口界面）。历史超级盘口传tradeDate后，
// 高低额量必须取对应日K，不能混用当前报价或用三秒4096快照估算瞬时极值。
export function StockInfo({
  tradeDate,
  selectedPrice,
  liveEvent,
}: {
  tradeDate?: string
  selectedPrice?: number
  liveEvent?: MarketEvent
} = {}) {
  const { code, quote, marketView } = useStock()
  const dailyRows = marketView.data?.kline ?? []
  const dayIndex = tradeDate == null
    ? -1
    : dailyRows.findIndex((row) => row.time.slice(0, 10) === tradeDate)
  const dayBar = dayIndex >= 0 ? dailyRows[dayIndex] : undefined
  const previousBar = dayIndex > 0 ? dailyRows[dayIndex - 1] : undefined
  const historical = dayBar != null
  const liveNumber = (key: string): number | undefined => {
    const value = liveEvent?.[key]
    if (value == null) return undefined
    const number = Number(value)
    return Number.isFinite(number) ? number : undefined
  }
  const price = historical
    ? selectedPrice ?? dayBar.close
    : liveNumber('price') ?? quote?.price
  const pc = historical
    ? previousBar?.close
    : liveNumber('prev_close') ?? quote?.prevClose
  const open = historical ? dayBar.open : liveNumber('open') ?? quote?.open
  const high = historical ? dayBar.high : liveNumber('high') ?? quote?.high
  const low = historical ? dayBar.low : liveNumber('low') ?? quote?.low
  const volume = historical ? dayBar.volume : quote?.vol
  const amount = historical ? dayBar.amount : quote?.amount
  const chg = price != null && pc != null ? price - pc : quote?.chg
  const chgPct = chg != null && pc ? (chg / pc) * 100 : quote?.chgPct
  // 今开/最高/最低相对昨收着色
  const openChg = open != null && pc ? open - pc : undefined
  const highChg = high != null && pc ? high - pc : undefined
  const lowChg = low != null && pc ? low - pc : undefined

  return (
    <div style={{ padding: '4px 8px', borderBottom: '1px solid #2a2a2a' }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          gap: 10,
          marginBottom: 4,
        }}
      >
        <span style={{ fontSize: 14, fontWeight: 600 }}>{code}</span>
        <span className={`price ${cls(chg)}`} style={{ fontSize: 15, fontWeight: 600 }}>
          {fmt(price)}
        </span>
        <span className={cls(chg)}>
          {chg != null ? (chg > 0 ? '+' : '') + chg.toFixed(2) : '--'}
        </span>
        <span className={cls(chg)}>
          {chgPct != null
            ? (chgPct > 0 ? '+' : '') + chgPct.toFixed(2) + '%'
            : '--'}
        </span>
      </div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '1px 12px',
          fontSize: 12,
        }}
      >
        <Row label={historical ? '开盘' : '今开'} value={fmt(open)} cls={cls(openChg)} />
        <Row label="昨收" value={fmt(pc)} cls="flat" />
        <Row label="最高" value={fmt(high)} cls={cls(highChg)} />
        <Row label="最低" value={fmt(low)} cls={cls(lowChg)} />
        <Row label="总量" value={fmtVol(volume)} cls="flat" />
        <Row label="总额" value={fmtVol(amount)} cls="flat" />
      </div>
    </div>
  )
}

function Row({
  label,
  value,
  cls,
}: {
  label: string
  value: string
  cls: string
}) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
      <span className="dim">{label}</span>
      <span className={cls}>{value}</span>
    </div>
  )
}
