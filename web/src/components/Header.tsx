import { useEffect, useState } from 'react'
import { api } from '../api/endpoints'
import { useStockNames } from '../data/useStockNames'
import { normalizeStockCode, useStock } from '../state/StockContext'
import type { StockPageMode } from '../state/StockContext'
import type { Status } from '../types'

function color(n: number | undefined): string {
  if (n === undefined || Number.isNaN(n)) return 'flat'
  if (n > 0) return 'up'
  if (n < 0) return 'down'
  return 'flat'
}

export function Header({
  view,
  onView,
}: {
  view: StockPageMode
  onView: (view: StockPageMode) => void
}) {
  const { code, setCode, marketView } = useStock()
  const names = useStockNames()
  const [input, setInput] = useState(code)
  const [status, setStatus] = useState<Status | null>(null)

  useEffect(() => {
    let cancelled = false
    const refreshStatus = () => {
      api
        .status()
        .then((next) => {
          if (!cancelled) setStatus(next)
        })
        .catch(() => {})
    }
    const refreshWhenVisible = () => {
      if (document.visibilityState === 'visible') refreshStatus()
    }

    refreshStatus()
    const timer = window.setInterval(refreshStatus, 15_000)
    window.addEventListener('focus', refreshStatus)
    document.addEventListener('visibilitychange', refreshWhenVisible)
    return () => {
      cancelled = true
      window.clearInterval(timer)
      window.removeEventListener('focus', refreshStatus)
      document.removeEventListener('visibilitychange', refreshWhenVisible)
    }
  }, [])

  useEffect(() => setInput(code), [code])

  const connect = async () => {
    try {
      await api.connect()
      const s = await api.status()
      setStatus(s)
    } catch {
      /* ignore */
    }
  }

  const commit = () => {
    const c = normalizeStockCode(input, code)
    setInput(c)
    if (c && c !== code) setCode(c)
  }

  const q = marketView.data?.quote
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
      <nav className="page-tabs" aria-label="个股页面">
        {(
          [
            ['kanpan', '看盘'],
            ['timeline', '分时'],
            ['superorder', '超级盘口'],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            className={view === key ? 'active' : ''}
            onClick={() => onView(key)}
          >
            {label}
          </button>
        ))}
      </nav>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && commit()}
        onBlur={commit}
        style={{ width: 86 }}
        placeholder="代码"
      />
      <span className="stock-name flat" title={code}>
        {names.get(code) ?? code}
      </span>
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
      {marketView.error && (
        <span className="dim">行情错误：{marketView.error.slice(0, 40)}</span>
      )}
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
