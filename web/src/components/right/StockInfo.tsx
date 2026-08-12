import { useStock } from '../../state/StockContext'

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

// 盘口上方的股票信息条（参考同花顺盘口界面）
export function StockInfo() {
  const { code, quote } = useStock()
  const pc = quote?.prevClose
  // 今开/最高/最低相对昨收着色
  const openChg = quote?.open != null && pc ? quote.open - pc : undefined
  const highChg = quote?.high != null && pc ? quote.high - pc : undefined
  const lowChg = quote?.low != null && pc ? quote.low - pc : undefined

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
        <span className={`price ${cls(quote?.chg)}`} style={{ fontSize: 15, fontWeight: 600 }}>
          {fmt(quote?.price)}
        </span>
        <span className={cls(quote?.chg)}>
          {quote?.chg != null ? (quote.chg > 0 ? '+' : '') + quote.chg.toFixed(2) : '--'}
        </span>
        <span className={cls(quote?.chg)}>
          {quote?.chgPct != null
            ? (quote.chgPct > 0 ? '+' : '') + quote.chgPct.toFixed(2) + '%'
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
        <Row label="今开" value={fmt(quote?.open)} cls={cls(openChg)} />
        <Row label="昨收" value={fmt(pc)} cls="flat" />
        <Row label="最高" value={fmt(quote?.high)} cls={cls(highChg)} />
        <Row label="最低" value={fmt(quote?.low)} cls={cls(lowChg)} />
        <Row label="总量" value={fmtVol(quote?.vol)} cls="flat" />
        <Row label="总额" value={fmtVol(quote?.amount)} cls="flat" />
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
