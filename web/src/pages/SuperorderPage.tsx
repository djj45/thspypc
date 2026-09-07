import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/endpoints'
import { StockInfo } from '../components/right/StockInfo'
import { useStock } from '../state/StockContext'
import { useSharedStockStream } from '../state/StockStreamContext'
import { useSuperorderMode } from '../state/superorderMode'
import { isRealtimeMarketSession, marketEventIdentity } from '../data/useStockStream'
import type {
  MarketEvent,
  OrderQueueSide,
  OrderQueues,
  ReplayIndex,
  ReplaySnapshot,
  SuperorderWindow,
} from '../types'
import { ReplayChart } from './ReplayChart'

// 实时轮询周期。tick 本身很轻：只有推送流显示有新数据（或距上次拉取
// 超 90s）才会真正请求 /api/superorder-replay；后端对该接口有 60s TTL
// 缓存，索引实际以约每分钟一次的粒度延伸。逐笔/队列/盘口本身由 WS
// 秒级推送，不受此限制。
const LIVE_REFRESH_MS = 15_000
// 挂单没有推送源（0x60 推送家族只有成交/撤单/队列），实时模式下用
// 窗口轮询补挂单/撤单明细；每次是一组真实的 7169/717x L2 查询，
// 不宜更快。逐笔/撤单的秒级更新走 WS 推送合并不经过这里。
const LIVE_WINDOW_POLL_MS = 15_000

function normalizeReplay(nextReplay: ReplayIndex): ReplayIndex {
  // 4260 当前日响应盘后偶尔尾随静态记录；页面只展示A股有效盘口时段。
  const visible = nextReplay.index.filter(
    (point) => point.time >= '09:15:00' && point.time <= '15:00:00',
  )
  return { ...nextReplay, count: visible.length, index: visible }
}

function pinnedPointTs(normalized: ReplayIndex | null): number | null {
  if (!normalized) return null
  // 明细接口717x仅覆盖连续交易，实时光标钉在14:56:29前的最后一个点，
  // 保证前后30秒窗口始终能同时拉到逐笔、挂单和撤单。
  const continuous = normalized.index.filter((point) => point.time <= '14:56:29')
  const point = continuous[continuous.length - 1] ?? normalized.index[normalized.index.length - 1]
  return point?.ts ?? null
}

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
  const total = queue?.total_order_count
  const countText = total == null
    ? `总 — 笔`
    : Number(total) > entries.length
      ? `总 ${String(total)} 笔 · 服务端可见前 ${entries.length} 笔`
      : `总 ${String(total)} 笔`
  return (
    <section className="queue-card">
      <div className="queue-head">
        <strong className={tone}>{title} {queue?.price != null ? Number(queue.price).toFixed(2) : '—'}</strong>
        <span className="dim">{countText}</span>
      </div>
      <div className="queue-strip">
        {entries.length ? entries.map((entry, index) => {
          const value = shares(entry)
          const major = typeof entry !== 'number' && entry.major
          return <span className={major ? 'major' : ''} key={index} title={`${value} 股`}>{Math.round(value / 100)}</span>
        }) : <span className="dim">空队列</span>}
      </div>
    </section>
  )
}

function SnapshotBook({
  data,
  live,
  bestBid,
  bestAsk,
  levelCount = 10,
}: {
  data: ReplaySnapshot | null
  live?: MarketEvent | null
  bestBid?: number
  bestAsk?: number
  levelCount?: 5 | 10
}) {
  // 实时模式下优先渲染 WS 十档推送（事件驱动，盘口变化即到）；推送尚未
  // 到达（刚打开/时段外/回放模式）时回退到光标时刻的回放快照。
  const liveSnapshot = useMemo(() => {
    if (!live?.bids?.length || !live?.asks?.length) return null
    return {
      time: '实时',
      price: Number(live.price ?? 0) || undefined,
      bids: live.bids.map((entry, index) => ({
        level: index + 1,
        price: entry?.[0],
        volume: entry?.[1],
      })),
      asks: live.asks.map((entry, index) => ({
        level: index + 1,
        price: entry?.[0],
        volume: entry?.[1],
      })),
    }
  }, [live])
  const snapshot = liveSnapshot ?? data?.snapshot
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
  // 与短线精灵相同的贴底策略：打开 tab 时滚到最新；之后新行到达时，
  // 只有当滚动条仍在底部（用户没有上翻历史）才继续贴底。
  const containerRef = useRef<HTMLDivElement | null>(null)
  const stickToBottomRef = useRef(true)

  useEffect(() => {
    const el = containerRef.current
    if (el) el.scrollTop = el.scrollHeight
    stickToBottomRef.current = true
  }, [])

  useEffect(() => {
    const el = containerRef.current
    if (el && stickToBottomRef.current) el.scrollTop = el.scrollHeight
  }, [rows])

  const handleScroll = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    stickToBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24
  }, [])

  return (
    <div ref={containerRef} onScroll={handleScroll} className="panel-body details-table">
      <table>
        <thead><tr><th className="left">时间</th><th>类型</th><th>方向</th><th>价格</th><th>数量</th><th>委托号</th></tr></thead>
        <tbody>
          {rows.length ? rows.map((row, index) => (
            <tr key={`${marketEventIdentity(row)}-${index}`}>
              <td className="left dim">{String(row.time ?? row.cancelled_time ?? row.cancelled_at ?? row.placed_time ?? row.placed_at ?? '—').slice(-8)}</td>
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
  const [mode, setMode] = useSuperorderMode()
  const historicalDate = tradeDate === today ? undefined : tradeDate
  const liveMode = mode === 'live' && !historicalDate
  // 午休/收盘后暂停两个实时轮询（推送流本身也会关闭）：否则每个 tick
  // 都是一组注定为空的 7169/717x L2 查询，白占通道还拖慢页面。时段
  // 边界（11:30/13:00/15:00）由定时器刷新，自动恢复。
  const [sessionOpen, setSessionOpen] = useState(isRealtimeMarketSession)
  useEffect(() => {
    const refresh = () => setSessionOpen(isRealtimeMarketSession())
    refresh()
    const timer = window.setInterval(refresh, 30_000)
    return () => window.clearInterval(timer)
  }, [])
  const liveActive = liveMode && sessionOpen

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
        // 轻量4096索引可能只有买卖量而没有buy1_price/sell1_price；完整价格会在
        // 随后的snapshot接口补齐，不能用索引价格是否非空过滤初始光标。
        const normalized = normalizeReplay(nextReplay)
        setReplay(normalized)
        setSelectedTs(pinnedPointTs(normalized))
        lastFetchRef.current = Date.now()
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

  // 实时模式：图表/明细跟随最新。刷新由推送流驱动——只有 WS 推送显示
  // 存在比索引尾部更新的数据（或距上次拉取超过90s兜底）才重拉当日索引，
  // 且数据未变化时跳过 setState：后端 60s 缓存只省 L2 查询，不省 ~200KB
  // 整表的传输与全量重渲染，每 15s 无脑重拉会让页面明显卡顿。
  const replayRef = useRef(replay)
  replayRef.current = replay
  const lastFetchRef = useRef(0)
  const streamNewestTsRef = useRef(0)
  // trade 推送带 timestamp、队列推送带 ts；depth 推送没有时间字段。
  const lastTrade = stream.trades[stream.trades.length - 1]
  const latestQueueTs = stream.latestQueues.buy?.ts ?? stream.latestQueues.sell?.ts
  for (const candidate of [lastTrade?.timestamp, lastTrade?.ts, latestQueueTs]) {
    if (typeof candidate === 'number' && candidate > streamNewestTsRef.current) {
      streamNewestTsRef.current = candidate
    }
  }
  const replayMissing = replay == null
  useEffect(() => {
    if (!liveActive || loading || replayMissing) return
    let current = true
    const tick = async () => {
      const prev = replayRef.current
      const lastIndexTs = prev?.index[prev.index.length - 1]?.ts ?? 0
      const sinceFetch = Date.now() - lastFetchRef.current
      // 后端 60s TTL 缓存内重拉只会拿到同一份整表，白传 ~200KB；
      // 推送流没有比索引尾部更新的数据时也不必拉。90s 兜底覆盖推送
      // 静默（如 WS 异常）但后端仍在产生数据的场景。
      if (sinceFetch < 50_000) return
      if (
        streamNewestTsRef.current <= lastIndexTs + 45 &&
        sinceFetch < 90_000
      ) {
        return
      }
      lastFetchRef.current = Date.now()
      try {
        const nextReplay = await api.superorderReplay(code)
        if (!current) return
        const normalized = normalizeReplay(nextReplay)
        const prevNow = replayRef.current
        const prevLast = prevNow?.index[prevNow.index.length - 1]?.ts
        const nextLast = normalized.index[normalized.index.length - 1]?.ts
        if (
          prevNow &&
          prevNow.index.length === normalized.index.length &&
          prevLast === nextLast
        ) {
          return
        }
        setReplay(normalized)
        const ts = pinnedPointTs(normalized)
        if (ts != null) setSelectedTs(ts)
      } catch {
        // 保留上一份索引继续展示；加载阶段的错误已由 load 呈现。
      }
    }
    const timer = window.setInterval(() => { void tick() }, LIVE_REFRESH_MS)
    return () => { current = false; window.clearInterval(timer) }
  }, [code, liveActive, loading, replayMissing])

  // 实时模式：明细窗锚定"当前时刻"周期刷新。逐笔/撤单已有 WS 秒级
  // 推送合并，挂单没有推送源，靠这里 ~15 秒一次的窗口拉取持续更新到
  // 最新（与光标驱动的窗口拉取互补，二者都以当前时刻封顶）。
  useEffect(() => {
    if (!liveActive || loading) return
    let current = true
    const poll = async () => {
      const now = new Date()
      const start = new Date(now.getTime() - 30_000)
      try {
        const nextWindow = await api.superorderWindow(
          code,
          localIso(start),
          localIso(now),
        )
        if (current) setWindowData(nextWindow)
      } catch {
        // 单次失败忽略；错误由光标路径呈现。
      }
    }
    const timer = window.setInterval(() => { void poll() }, LIVE_WINDOW_POLL_MS)
    return () => { current = false; window.clearInterval(timer) }
  }, [code, liveActive, loading])

  // 切入实时模式（或把日期切回当日）时立即钉到最新点，不等下一个刷新周期。
  // 刻意只依赖 liveMode：日期切换会触发上面的加载流程自行重定位。
  useEffect(() => {
    if (!liveMode) return
    const ts = pinnedPointTs(replay)
    if (ts != null) setSelectedTs(ts)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveMode])

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
      Date.now(),
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

  const handleSelect = useCallback((ts: number) => {
    // 实时模式下点选非最新点 = 要回看历史，自动切换为历史模式；
    // 再点工具栏「实时」即可回到跟随最新。
    if (liveMode) {
      const latest = pinnedPointTs(replay)
      if (latest == null || ts !== latest) setMode('replay')
    }
    setSelectedTs(ts)
  }, [liveMode, replay, setMode])
  const buyQueue = stream.latestQueues.buy ?? queues?.buy
  const sellQueue = stream.latestQueues.sell ?? queues?.sell
  const rows = useMemo(() => {
    let source: MarketEvent[]
    if (tab === 'trades') {
      // 实时成交只在看当日时并入；历史日期不混入今天的推送。
      const live = historicalDate ? [] : stream.trades.slice(-100)
      source = [...(windowData?.trades ?? []), ...live]
    } else {
      const details = windowData?.details
      // 撤单有 WS 推送，同样并入实时流（按事件身份去重）。
      const liveCancels = historicalDate
        ? []
        : stream.events.filter((event) => event.event === 'cancel')
      source = tab === 'orders'
        ? (details?.orders ?? []) as MarketEvent[]
        : [
            ...(details?.buy_cancels ?? []),
            ...(details?.sell_cancels ?? []),
            ...liveCancels,
          ] as MarketEvent[]
    }
    const seen = new Set<string>()
    return source.filter((row) => {
      const identity = marketEventIdentity(row)
      if (seen.has(identity)) return false
      seen.add(identity)
      return true
    })
  }, [stream.trades, stream.events, tab, windowData, historicalDate])
  const latestReplayTs = replay?.index[replay.index.length - 1]?.ts
  const atLatestSnapshot = selectedTs != null && selectedTs === latestReplayTs
  const detailHint = detailWindowHint(snapshot?.snapshot.time)

  return (
    <main className="subpage superorder-page">
      <section className="panel replay-chart-panel">
        <div className="panel-title replay-toolbar">
          <span>4096 盘口回放 · {replay?.count ?? 0} 个快照</span>
          <span className="mode-toggle" title={historicalDate ? '历史交易日仅支持回放' : '实时：图表与明细跟随最新；历史：按光标回放'}>
            <button className={liveMode ? 'active' : ''} disabled={!!historicalDate} onClick={() => setMode('live')}>实时</button>
            <button className={!liveMode ? 'active' : ''} onClick={() => setMode('replay')}>历史</button>
          </span>
          <span className="dim">{liveMode ? `逐笔/撤单/队列秒级 · 挂单约15秒 · 图表约每分钟 · 单击历史点切换回放` : '单击图表移动光标 · 底部滑块缩放'}</span>
          <label>交易日 <input type="date" value={tradeDate} onChange={(event) => setTradeDate(event.target.value)} /></label>
          <span className="stream-state">实时：{stream.state}</span>
          {loading && <span className="dim">加载中…</span>}
          {(error || stream.error) && <span className="down">{(error || stream.error).slice(0, 100)}</span>}
        </div>
        <div className="chart-host">
          <ReplayChart points={replay?.index ?? []} selectedTs={selectedTs} onSelect={handleSelect} />
        </div>
      </section>
      <aside className="superorder-side">
        <section className="panel stock-summary"><div className="panel-title">个股概览</div><div className="panel-body"><StockInfo tradeDate={historicalDate} selectedPrice={historicalDate ? snapshot?.snapshot.price : undefined} liveEvent={stream.latestDepth} /></div></section>
        <section className="panel snapshot-panel"><div className="panel-title">{liveMode && stream.latestDepth ? '实时十档' : `光标时刻${historicalDate ? '五档（历史4417）' : '十档'}`}</div><div className="panel-body"><SnapshotBook data={snapshot} live={liveMode ? stream.latestDepth : undefined} bestBid={atLatestSnapshot ? Number(buyQueue?.price ?? 0) || undefined : undefined} bestAsk={atLatestSnapshot ? Number(sellQueue?.price ?? 0) || undefined : undefined} levelCount={historicalDate ? 5 : 10} /></div></section>
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
        <DetailsTable key={tab} rows={rows} />
      </section>
    </main>
  )
}
