import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api/endpoints'
import { StockInfo } from '../components/right/StockInfo'
import { useStock } from '../state/StockContext'
import { useSharedStockStream } from '../state/StockStreamContext'
import { marketEventIdentity } from '../data/useStockStream'
import type {
  MarketEvent,
  OrderQueueSide,
  OrderQueues,
  ReplayIndex,
  ReplaySnapshot,
  SuperorderWindow,
} from '../types'
import { ReplayChart } from './ReplayChart'

function localDate(value = new Date()): string {
  const pad = (part: number) => String(part).padStart(2, '0')
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`
}

function localIso(value: Date): string {
  const pad = (part: number) => String(part).padStart(2, '0')
  return `${localDate(value)}T${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}`
}

function detailWindowHint(time: string | undefined): string {
  if (!time) return '光标前后 30 秒'
  if (time < '09:30:00') return '开盘集合竞价无7169/717x明细；请点选09:30后'
  if (time > '11:30:00' && time < '13:00:00') return '午间休市无逐笔/挂撤明细'
  if (time >= '14:57:00') return '尾盘竞价明细协议暂不可用；请点选14:57前'
  return '光标前后 30 秒'
}

function QueuePanel({
  title,
  queue,
  tone,
}: {
  title: string
  queue?: OrderQueueSide | MarketEvent
  tone: 'up' | 'down'
}) {
  const entries = (queue?.entries ?? []) as Array<number | { shares?: number; hands?: number; major?: boolean }>
  const shares = (entry: typeof entries[number]) => typeof entry === 'number' ? entry : Number(entry.shares ?? (entry.hands ?? 0) * 100)
  return (
    <section className="queue-card">
      <div className="queue-head">
        <strong className={tone}>{title} {queue?.price != null ? Number(queue.price).toFixed(2) : '—'}</strong>
        <span className="dim">总 {String(queue?.total_order_count ?? '—')} 笔 · 可见 {String(queue?.visible_count ?? entries.length)}</span>
      </div>
      <div className="queue-strip">
        {entries.length ? entries.map((entry, index) => {
          const value = shares(entry)
          const major = typeof entry !== 'number' && entry.major
          return <span className={major ? 'major' : ''} key={index} title={`${value} 股`}>{Math.round(value / 100)}</span>
        }) : <span className="dim">空队列</span>}
      </div>
      {Boolean(queue?.truncated) && <div className="dim">服务端仅返回可见队列片段</div>}
    </section>
  )
}

function SnapshotBook({
  data,
  bestBid,
  bestAsk,
  levelCount = 10,
}: {
  data: ReplaySnapshot | null
  bestBid?: number
  bestAsk?: number
  levelCount?: 5 | 10
}) {
  const snapshot = data?.snapshot
  if (!snapshot) return <div className="dim empty-state">在时间轴上点选一个盘口时刻</div>
  const inferBest = (
    rows: typeof snapshot.bids,
    side: 'bid' | 'ask',
  ): number | undefined => {
    const known = rows
      .slice(1)
      .map((row) => Number(row.price))
      .filter((price) => Number.isFinite(price) && price > 0)
    if (known.length < 2) return undefined
    const steps = known
      .slice(1)
      .map((price, index) => Math.abs(price - known[index]))
      .filter((step) => step > 0)
    if (!steps.length) return undefined
    const step = Math.min(...steps)
    return Number((known[0] + (side === 'bid' ? step : -step)).toFixed(3))
  }
  const shownBestBid = bestBid ?? inferBest(snapshot.bids, 'bid')
  const shownBestAsk = bestAsk ?? inferBest(snapshot.asks, 'ask')
  const visibleAsks = snapshot.asks.filter((row) => row.level <= levelCount)
  const visibleBids = snapshot.bids.filter((row) => row.level <= levelCount)
  return (
    <div className="replay-book">
      <div className="replay-price">{snapshot.time} <strong>{snapshot.price?.toFixed(2)}</strong></div>
      {[...visibleAsks].reverse().map((row) => (
        <div className="replay-level" key={`s-${row.level}`}><span>卖{row.level}</span><span className="down">{(row.price ?? (row.level === 1 ? shownBestAsk : undefined))?.toFixed(2) ?? '—'}</span><span>{Number(row.volume ?? 0).toLocaleString()}</span></div>
      ))}
      <div className="book-divider" />
      {visibleBids.map((row) => (
        <div className="replay-level" key={`b-${row.level}`}><span>买{row.level}</span><span className="up">{(row.price ?? (row.level === 1 ? shownBestBid : undefined))?.toFixed(2) ?? '—'}</span><span>{Number(row.volume ?? 0).toLocaleString()}</span></div>
      ))}
      {(snapshot.bids[0]?.price == null || snapshot.asks[0]?.price == null) && (
        <div className="dim">一档价由当前队列或相邻档位价差回填</div>
      )}
    </div>
  )
}

function DetailsTable({ rows }: { rows: MarketEvent[] }) {
  return (
    <div className="panel-body details-table">
      <table>
        <thead><tr><th className="left">时间</th><th>类型</th><th>方向</th><th>价格</th><th>数量</th><th>委托号</th></tr></thead>
        <tbody>
          {rows.length ? rows.map((row, index) => (
            <tr key={`${marketEventIdentity(row)}-${index}`}>
              <td className="left dim">{String(row.time ?? row.cancelled_time ?? row.placed_time ?? '—').slice(-8)}</td>
              <td>{String(row.event ?? 'trade')}</td>
              <td className={String(row.side ?? row.direction).match(/sell|卖|5/i) ? 'down' : 'up'}>{String(row.side ?? row.direction ?? '—')}</td>
              <td>{Number(row.price ?? row.dt10 ?? 0).toFixed(2)}</td>
              <td>{Number(row.volume ?? row.dt13 ?? 0).toLocaleString()}</td>
              <td>{String(row.order_id ?? row.delegate_a ?? row.delegate_b ?? '—')}</td>
            </tr>
          )) : <tr><td colSpan={6} className="left dim">当前窗口暂无明细</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

export function SuperorderPage() {
  const { code } = useStock()
  const today = localDate()
  const [tradeDate, setTradeDate] = useState(today)
  const [replay, setReplay] = useState<ReplayIndex | null>(null)
  const [snapshot, setSnapshot] = useState<ReplaySnapshot | null>(null)
  const [queues, setQueues] = useState<OrderQueues | null>(null)
  const [windowData, setWindowData] = useState<SuperorderWindow | null>(null)
  const [selectedTs, setSelectedTs] = useState<number | null>(null)
  const [tab, setTab] = useState<'trades' | 'orders' | 'cancels'>('trades')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const stream = useSharedStockStream()
  const historicalDate = tradeDate === today ? undefined : tradeDate

  useEffect(() => {
    let current = true
    setLoading(true)
    setError('')
    setReplay(null)
    setSnapshot(null)
    setWindowData(null)
    setSelectedTs(null)
    const load = async () => {
      try {
        await api.stockReady(code)
        if (!current) return
        const nextReplay = await api.superorderReplay(code, historicalDate)
        if (!current) return
        // 4260 当前日响应盘后偶尔尾随静态记录；页面只展示A股有效盘口时段。
        // 明细接口717x仅覆盖连续交易，初始光标必须落在14:56:30之前，才能让
        // 默认的前后30秒窗口同时展示逐笔、挂单和撤单，而不是一打开就进入
        // 14:57后的尾盘竞价空窗口。
        const visible = nextReplay.index.filter(
          (point) => point.time >= '09:15:00' && point.time <= '15:00:00',
        )
        const normalized = {
          ...nextReplay,
          count: visible.length,
          index: visible,
        }
        setReplay(normalized)
        const continuous = visible.filter((point) => point.time <= '14:56:29')
        // 轻量4096索引可能只有买卖量而没有buy1_price/sell1_price；完整价格会在
        // 随后的snapshot接口补齐，不能用索引价格是否非空过滤初始光标。
        const initial = continuous[continuous.length - 1] ?? visible[visible.length - 1]
        setSelectedTs(initial?.ts ?? null)
      } catch (reason) {
        if (current) setError(reason instanceof Error ? reason.message : String(reason))
      } finally {
        if (current) setLoading(false)
      }
      if (!current) return
      try {
        const nextQueues = await api.orderQueues(code, historicalDate)
        if (current) setQueues(nextQueues)
      } catch (reason) {
        if (current) setError(reason instanceof Error ? reason.message : String(reason))
      }
    }
    void load()
    return () => { current = false }
  }, [code, historicalDate])

  useEffect(() => {
    if (selectedTs == null) return
    let current = true
    setSnapshot(null)
    setWindowData(null)
    setError('')
    const center = new Date(selectedTs * 1000)
    const morningOpen = new Date(center)
    morningOpen.setHours(9, 30, 0, 0)
    const morningClose = new Date(center)
    morningClose.setHours(11, 30, 0, 0)
    const afternoonOpen = new Date(center)
    afternoonOpen.setHours(13, 0, 0, 0)
    const afternoonClose = new Date(center)
    afternoonClose.setHours(14, 56, 59, 0)
    const session = center >= morningOpen && center <= morningClose
      ? { start: morningOpen, end: morningClose }
      : center >= afternoonOpen && center <= afternoonClose
        ? { start: afternoonOpen, end: afternoonClose }
        : null
    const start = session == null ? center : new Date(Math.max(
      session.start.getTime(),
      center.getTime() - 30_000,
    ))
    const end = session == null ? center : new Date(Math.min(
      session.end.getTime(),
      center.getTime() + 30_000,
    ))
    const timer = window.setTimeout(() => {
      void api.superorderSnapshot(code, selectedTs, historicalDate)
        .then((nextSnapshot) => {
          if (current) setSnapshot(nextSnapshot)
        })
        .catch((reason) => {
          if (current) {
            const message = reason instanceof Error ? reason.message : String(reason)
            setError(/HTTP 502|timed out/i.test(message) ? '明细窗口暂不可用（L2返回空或超时）' : message)
          }
        })
      if (session == null) {
        setWindowData({
          code,
          start: localIso(center),
          end: localIso(center),
          trades: [],
          details: { orders: [], buy_cancels: [], sell_cancels: [], events: [] },
        })
        return
      }
      void api.superorderWindow(code, localIso(start), localIso(end))
        .then((nextWindow) => {
          if (current) setWindowData(nextWindow)
        })
        .catch((reason) => {
          if (current) setError(reason instanceof Error ? reason.message : String(reason))
        })
    }, 120)
    return () => { current = false; window.clearTimeout(timer) }
  }, [code, historicalDate, selectedTs])

  const selectTs = useCallback((ts: number) => setSelectedTs(ts), [])
  const buyQueue = stream.latestQueues.buy ?? queues?.buy
  const sellQueue = stream.latestQueues.sell ?? queues?.sell
  const rows = useMemo(() => {
    let source: MarketEvent[]
    if (tab === 'trades') {
      source = [...(windowData?.trades ?? []), ...stream.trades.slice(-100)]
    } else {
      const details = windowData?.details
      source = tab === 'orders'
        ? (details?.orders ?? []) as MarketEvent[]
        : [...(details?.buy_cancels ?? []), ...(details?.sell_cancels ?? [])] as MarketEvent[]
    }
    const seen = new Set<string>()
    return source.filter((row) => {
      const identity = marketEventIdentity(row)
      if (seen.has(identity)) return false
      seen.add(identity)
      return true
    })
  }, [stream.trades, tab, windowData])
  const latestReplayTs = replay?.index[replay.index.length - 1]?.ts
  const atLatestSnapshot = selectedTs != null && selectedTs === latestReplayTs
  const detailHint = detailWindowHint(snapshot?.snapshot.time)

  return (
    <main className="subpage superorder-page">
      <section className="panel replay-chart-panel">
        <div className="panel-title replay-toolbar">
          <span>4096 盘口回放 · {replay?.count ?? 0} 个快照</span>
          <span className="dim">单击图表移动光标 · 底部滑块缩放</span>
          <label>交易日 <input type="date" value={tradeDate} onChange={(event) => setTradeDate(event.target.value)} /></label>
          <span className="stream-state">实时：{stream.state}</span>
          {loading && <span className="dim">加载中…</span>}
          {(error || stream.error) && <span className="down">{(error || stream.error).slice(0, 100)}</span>}
        </div>
        <div className="chart-host">
          <ReplayChart points={replay?.index ?? []} selectedTs={selectedTs} onSelect={selectTs} />
        </div>
      </section>
      <aside className="superorder-side">
        <section className="panel stock-summary"><div className="panel-title">个股概览</div><div className="panel-body"><StockInfo tradeDate={historicalDate} selectedPrice={historicalDate ? snapshot?.snapshot.price : undefined} liveEvent={stream.latestDepth} /></div></section>
        <section className="panel snapshot-panel"><div className="panel-title">光标时刻{historicalDate ? '五档（历史4417）' : '十档'}</div><div className="panel-body"><SnapshotBook data={snapshot} bestBid={atLatestSnapshot ? Number(buyQueue?.price ?? 0) || undefined : undefined} bestAsk={atLatestSnapshot ? Number(sellQueue?.price ?? 0) || undefined : undefined} levelCount={historicalDate ? 5 : 10} /></div></section>
        <section className="panel queues-panel">
          <div className="panel-title">买一 / 卖一委托队列</div>
          <div className="panel-body queue-body">
            <QueuePanel title="买一" queue={buyQueue} tone="up" />
            <QueuePanel title="卖一" queue={sellQueue} tone="down" />
          </div>
        </section>
      </aside>
      <section className="panel replay-details">
        <div className="panel-title detail-tabs">
          {(['trades', 'orders', 'cancels'] as const).map((key) => <button key={key} className={tab === key ? 'active' : ''} onClick={() => setTab(key)}>{key === 'trades' ? '逐笔成交' : key === 'orders' ? '挂单' : '撤单'}</button>)}
          <span className="dim">{detailHint}</span>
        </div>
        <DetailsTable rows={rows} />
      </section>
    </main>
  )
}
