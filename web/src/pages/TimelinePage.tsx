import { useEffect, useMemo, useState } from 'react'
import { api } from '../api/endpoints'
import { TimelineChart } from '../components/center/TimelineChart'
import { StockInfo } from '../components/right/StockInfo'
import { useStock } from '../state/StockContext'
import { useSharedStockStream } from '../state/StockStreamContext'
import { isRealtimeMarketSession } from '../data/useStockStream'
import type { Depth, MarketEvent } from '../types'

function localIso(value: Date): string {
  const pad = (part: number) => String(part).padStart(2, '0')
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}T${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}`
}

function recentSessionWindow(): [string, string] {
  const now = new Date()
  const open = new Date(now)
  open.setHours(9, 30, 0, 0)
  const close = new Date(now)
  close.setHours(15, 0, 0, 0)
  const end = now < open ? new Date(open.getTime() + 60_000) : now > close ? close : now
  const start = new Date(Math.max(open.getTime(), end.getTime() - 120_000))
  return [localIso(start), localIso(end)]
}

function eventTime(event: MarketEvent): string {
  if (event.time) return String(event.time).slice(-8)
  const ts = Number(event.timestamp ?? event.ts ?? event.dt1)
  return Number.isFinite(ts) && ts > 0
    ? new Date(ts * 1000).toLocaleTimeString('zh-CN', { hour12: false })
    : '--:--:--'
}

function directionClass(event: MarketEvent): string {
  const direction = String(event.direction ?? event.side ?? event.dt20 ?? '')
  return /sell|卖|5/i.test(direction) ? 'down' : /buy|买|1/i.test(direction) ? 'up' : 'flat'
}

function depthEventToBook(event: MarketEvent | undefined): Depth | null {
  if (!event?.bids?.length && !event?.asks?.length) return null
  const levels = (rows: Array<[number, number]> | undefined) =>
    (rows ?? []).map(([price, qty], index) => ({
      level: String(index + 1),
      price: Number(price),
      qty: Number(qty),
      amount: Number(price) * Number(qty),
    }))
  return {
    code: event.code,
    buy: levels(event.bids),
    sell: levels(event.asks),
  }
}

function TickTape({ rows }: { rows: MarketEvent[] }) {
  return (
    <div className="panel-body tick-tape">
      <table>
        <thead>
          <tr><th className="left">时间</th><th>价格</th><th>成交量</th><th>方向</th></tr>
        </thead>
        <tbody>
          {rows.length ? rows.map((row, index) => (
            <tr key={`${eventTime(row)}-${String(row.seq ?? index)}`}>
              <td className="left dim">{eventTime(row)}</td>
              <td className={directionClass(row)}>{Number(row.price ?? row.dt10 ?? 0).toFixed(2)}</td>
              <td>{Number(row.volume ?? row.dt13 ?? 0).toLocaleString()}</td>
              <td className={directionClass(row)}>{String(row.direction ?? row.side ?? row.dt20 ?? '—')}</td>
            </tr>
          )) : (
            <tr><td colSpan={4} className="dim left">当前窗口暂无逐笔成交</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function TenLevelBook({ depth }: { depth: Depth | null }) {
  const rows = useMemo(() => {
    if (!depth) return []
    return [
      ...[...(depth.sell ?? [])].reverse().map((row) => ({ ...row, side: 'sell' })),
      ...(depth.buy ?? []).map((row) => ({ ...row, side: 'buy' })),
    ]
  }, [depth])
  return (
    <div className="ten-book">
      {rows.length ? rows.map((row) => (
        <div className="depth-row" key={`${row.side}-${row.level}`}>
          <span className="lvl">{row.level}</span>
          <span className={row.side === 'sell' ? 'down' : 'up'}>{row.price.toFixed(2)}</span>
          <span>{row.qty.toLocaleString()}</span>
          <span className="dim">{row.amount >= 10_000 ? `${(row.amount / 10_000).toFixed(1)}万` : row.amount.toFixed(0)}</span>
        </div>
      )) : <div className="dim empty-state">暂无十档盘口</div>}
    </div>
  )
}

export function TimelinePage() {
  const { code } = useStock()
  const stream = useSharedStockStream()
  const [history, setHistory] = useState<MarketEvent[]>([])
  const [depth, setDepth] = useState<Depth | null>(null)
  const [error, setError] = useState('')
  const liveDepth = useMemo(
    () => depthEventToBook(stream.latestDepth),
    [stream.latestDepth],
  )

  useEffect(() => {
    let current = true
    setHistory([])
    setDepth(null)
    setError('')
    // 十档和逐笔独立结算：一个接口失败不能把另一个已经成功的面板清空。
    void api.depth(code, 10).then((result) => {
      if (current) setDepth(result)
    }).catch((reason) => {
      if (current) setError(reason instanceof Error ? reason.message : String(reason))
    })

    // 盘后没有实时逐笔流；14:57-15:00 又是尾盘竞价，查询7175/7170/7171
    // 连续交易窗口只会空等。官方客户端盘后只加载历史分时/盘口，因此这里也
    // 不请求超级盘口窗口。盘中只取7169成交，不再附带挂单撤单三路查询。
    if (isRealtimeMarketSession()) {
      const [start, end] = recentSessionWindow()
      void api.superorderTrades(code, start, end).then((result) => {
        if (current) setHistory(result)
      }).catch((reason) => {
        if (current) setError(reason instanceof Error ? reason.message : String(reason))
      })
    }
    return () => { current = false }
  }, [code])

  useEffect(() => {
    if (liveDepth) setError('')
  }, [liveDepth])

  const rows = useMemo(
    () => [...history, ...stream.trades].slice(-300).reverse(),
    [history, stream.trades],
  )

  return (
    <main className="subpage timeline-page">
      <section className="panel timeline-main">
        <div className="panel-title">
          分时走势
          <span className="stream-state">实时：{stream.state}</span>
          {(error || stream.error) && <span className="down">{(error || stream.error).slice(0, 90)}</span>}
        </div>
        <div className="chart-host"><TimelineChart /></div>
      </section>
      <aside className="subpage-side">
        <section className="panel quote-book">
          <div className="panel-title">十档盘口</div>
          <div className="panel-body">
            <StockInfo liveEvent={stream.latestDepth} />
            <TenLevelBook depth={liveDepth ?? depth} />
          </div>
        </section>
        <section className="panel tape-panel">
          <div className="panel-title">逐笔成交 <span className="dim">最近 2 分钟 + 实时</span></div>
          <TickTape rows={rows} />
        </section>
      </aside>
    </main>
  )
}
