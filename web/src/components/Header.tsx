import { useEffect, useState } from 'react'
import { api } from '../api/endpoints'
import { useData } from '../data/useData'
import { useStock } from '../state/StockContext'

function color(n: number | undefined): string {
  if (n === undefined || Number.isNaN(n)) return 'flat'
  if (n > 0) return 'up'
  if (n < 0) return 'down'
  return 'flat'
}

export function Header() {
  const { code, setCode, setQuote } = useStock()
  const [input, setInput] = useState(code)
  const [status, setStatus] = useState<{
    connected: boolean
    server: string
    account_kind: string
  } | null>(null)

  // 拉选中股票的行情
  const { data, error } = useData(() => api.quote([code]), [code])

  useEffect(() => {
      if (data && data[0]) {
        const q = data[0]
        const price = q.dt10
        const prevClose = q.dt6
        const chg =
          price != null && prevClose != null ? price - prevClose : undefined
        const chgPct =
          chg != null && prevClose ? (chg / prevClose) * 100 : undefined
        setQuote({
          price,
          prevClose,
          open: q.dt7,
          high: q.dt8,
          low: q.dt9,
          vol: q.dt13,
          amount: q.dt19,
          chg,
          chgPct,
        })
      }
  }, [data, setQuote])

  useEffect(() => {
    api.status().then(setStatus).catch(() => {})
  }, [])

  const connect = async () => {
    try {
      await api.connect()
      const s = await api.status()
      setStatus(s as never)
    } catch {
      /* ignore */
    }
  }

  const commit = () => {
    const c = input.trim()
    if (c && c !== code) setCode(c)
  }

  const q = data?.[0]
  const price = q?.dt10
  const prevClose = q?.dt6
  // 涨跌额 = 现价 - 昨收（dt66 盘后可能不准，前端按昨收自算涨跌幅更可靠）
  const chgAmt =
    price != null && prevClose != null ? price - prevClose : undefined
  const chgPct =
    chgAmt != null && prevClose ? (chgAmt / prevClose) * 100 : undefined
  const sign = (v: number | undefined) =>
    v === undefined ? '' : v > 0 ? '+' : ''

  return (
    <header className="header">
      <span className="title">同花顺看盘 · thspypc</span>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && commit()}
        onBlur={commit}
        style={{ width: 86 }}
        placeholder="代码"
      />
      <span className="stock-name flat">{code}</span>
      {price != null && (
        <>
          <span className={`price ${color(chgAmt)}`}>{price.toFixed(2)}</span>
          {chgAmt != null && (
            <span className={color(chgAmt)}>
              {sign(chgAmt)}
              {chgAmt.toFixed(2)}
            </span>
          )}
          {chgPct != null && (
            <span className={color(chgAmt)}>
              {sign(chgPct)}
              {chgPct.toFixed(2)}%
            </span>
          )}
        </>
      )}
      {error && <span className="dim">行情错误：{error.slice(0, 40)}</span>}
      <span className="status-dot">
        <span className={`dot ${status?.connected ? 'on' : ''}`} />
        {status
          ? status.connected
            ? `已连接 ${status.server} (${status.account_kind})`
            : '未连接'
          : '查询中…'}
      </span>
      <button onClick={connect}>连接</button>
    </header>
  )
}
