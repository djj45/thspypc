import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { api } from '../api/endpoints'
import {
  isRecoverableRequestError,
  recoverableRetryDelay,
} from '../api/client'
import type { DataState } from '../data/useData'
import type {
  AuctionPoint,
  Kline,
  MarketView,
  MarketViewFast,
  TimelinePoint,
} from '../types'

export interface QuoteInfo {
  price?: number
  prevClose?: number
  open?: number
  high?: number
  low?: number
  vol?: number
  amount?: number
  chg?: number
  chgPct?: number
}

// 周期字符串与后端 /api/kline 完全一致（client._KLINE_PERIOD_KEYS）：
// 分钟周期必须写 'Nmin'，裸 '60'/'30' 会被后端 400 拒绝。
export const KLINE_PERIODS = [
  'day',
  'week',
  'month',
  'quarter',
  'year',
  '60min',
  '30min',
  '15min',
  '5min',
  '1min',
] as const
export type KlinePeriod = (typeof KLINE_PERIODS)[number]
type IntradayPoint = AuctionPoint & TimelinePoint

interface TaggedKline {
  code: string
  period: KlinePeriod
  fuquan: string
  rows: Kline[]
}

/**
 * 列表导航源：getCodes 返回该列表“当前”的完整代码顺序（点击后排序变化也跟随）；
 * revealCode 负责让虚拟列表把键盘/滚轮切到的目标行滚进可视区。
 */
export interface StockNavSource {
  getCodes: () => string[]
  revealCode?: (code: string) => void
}

interface StockCtx {
  code: string
  /** 选中股票；source=点击来源列表（注册为键盘/滚轮切换的顺序源） */
  setCode: (code: string, source?: StockNavSource) => void
  period: KlinePeriod
  setPeriod: (period: KlinePeriod) => void
  fuquan: string
  setFuquan: (fuquan: string) => void
  quote: QuoteInfo | null
  marketView: DataState<MarketView>
  intradayState: DataState<IntradayPoint[]>
  klineState: DataState<Kline[]>
  /** 上/下一只：有列表上下文按列表当前顺序（首尾循环），否则按全市场代码升序 */
  navigate: (dir: 1 | -1) => void
  /** 全市场代码（升序）注册口，RankPanel 加载后填充，供无列表上下文时回退 */
  globalCodesRef: React.MutableRefObject<string[]>
}

const emptyMarketView: DataState<MarketView> = {
  data: null,
  loading: true,
  error: '',
  refresh: () => {},
}
const emptyKline: DataState<Kline[]> = {
  data: null,
  loading: true,
  error: '',
  refresh: () => {},
}

const Ctx = createContext<StockCtx>({
  code: '600519',
  setCode: () => {},
  period: 'day',
  setPeriod: () => {},
  fuquan: 'Q',
  setFuquan: () => {},
  quote: null,
  marketView: emptyMarketView,
  intradayState: {
    data: null,
    loading: true,
    error: '',
    refresh: () => {},
  },
  klineState: emptyKline,
  navigate: () => {},
  globalCodesRef: { current: [] },
})

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

// 只恢复最终停留的股票。后端 Web 路由会把单次协议工作限制在浏览器超时以内，
// 这里持续退避处理短暂的 502/网络超时；错误会立即上屏，但当前任务在后台
// 自恢复。已经切走或刷新替换的旧任务会在 250ms 内退出，不占住通道闸门。
async function retryCurrentRequest<T>(
  request: () => Promise<T>,
  isCurrent: () => boolean,
  onRecoverableError?: (error: unknown) => void,
): Promise<T> {
  let failureCount = 0
  for (;;) {
    try {
      return await request()
    } catch (error) {
      if (!isRecoverableRequestError(error) || !isCurrent()) {
        throw error
      }
      failureCount += 1
      onRecoverableError?.(error)
      const deadline = Date.now() + recoverableRetryDelay(failureCount)
      while (isCurrent() && Date.now() < deadline) {
        await new Promise((resolve) =>
          setTimeout(resolve, Math.min(250, deadline - Date.now())),
        )
      }
      if (!isCurrent()) throw error
    }
  }
}

// 盘口和 K 线用于首屏，切股后立即发起。分时返回更大，且与 K 线
// 共用市场 L2 socket，只保留一个人无感的短合并窗口。
const INTRADAY_SWITCH_COALESCE_MS = 100
const KLINE_SWITCH_COALESCE_MS = 180
const AUCTION_POLL_INTERVAL_MS = 3_000
const AUCTION_WINDOWS = [
  { start: [9, 15], end: [9, 26] },
  { start: [14, 57], end: [15, 1] },
] as const

// 同花顺会优先用本地图表数据绘制再后台刷新。Web 保留最近看过的
// 股票/周期/复权组合，避免切回时先清空图表。
const KLINE_CACHE_LIMIT = 128

function klineCacheKey(code: string, period: KlinePeriod, fuquan: string) {
  return `${code}\u0000${period}\u0000${fuquan}`
}

// 数据通道闸门：同一通道最多 1 个在途请求，快速连切时排队任务不断被
// 最新代码替换 —— 后端 socket 不积压废请求，停下后必拉最终代码。
function useLaneGate() {
  const busyRef = useRef(false)
  const taskRef = useRef<(() => Promise<void>) | null>(null)
  return useCallback((task: () => Promise<void>) => {
    taskRef.current = task
    if (busyRef.current) return
    const go = async () => {
      busyRef.current = true
      try {
        while (taskRef.current) {
          const t = taskRef.current
          taskRef.current = null
          await t()
        }
      } finally {
        busyRef.current = false
      }
    }
    void go()
  }, [])
}

export type StockPageMode = 'kanpan' | 'timeline' | 'superorder'

export function normalizeStockCode(
  value: string | null | undefined,
  fallback = '600519',
): string {
  const text = value?.trim().toUpperCase() ?? ''
  const match = text.match(/^(?:\d{6}|1[AB]\d{4})/)
  return match?.[0] ?? fallback
}

export function StockProvider({
  children,
  mode = 'kanpan',
}: {
  children: ReactNode
  mode?: StockPageMode
}) {
  const [code, setCode] = useState(
    () =>
      normalizeStockCode(
        new URLSearchParams(window.location.search).get('code'),
      ),
  )
  const [period, setPeriod] = useState<KlinePeriod>('day')
  const [fuquan, setFuquan] = useState('Q')
  const [fast, setFast] = useState<MarketViewFast | null>(null)
  const [intraday, setIntraday] = useState<{
    code: string
    rows: IntradayPoint[]
  } | null>(null)
  const [kline, setKline] = useState<TaggedKline | null>(null)
  const [fastLoading, setFastLoading] = useState(true)
  const [intradayLoading, setIntradayLoading] = useState(true)
  const [klineLoading, setKlineLoading] = useState(true)
  const [fastError, setFastError] = useState('')
  const [intradayError, setIntradayError] = useState('')
  const [klineError, setKlineError] = useState('')
  const [refreshTick, setRefreshTick] = useState(0)
  const codeRef = useRef(code)
  codeRef.current = code
  const fastLane = useLaneGate()
  const intradayLane = useLaneGate()
  const klineLane = useLaneGate()
  const klineCacheRef = useRef(new Map<string, TaggedKline>())
  // 键盘/滚轮切换股票：最近点击的列表（顺序源）+ 全市场代码（升序回退）
  const navListRef = useRef<StockNavSource | null>(null)
  const globalCodesRef = useRef<string[]>([])

  const setCodeWithSource = useCallback(
    (next: string, source?: StockNavSource) => {
      if (source) navListRef.current = source
      setCode((current) => normalizeStockCode(next, current))
    },
    [],
  )

  const navigate = useCallback(
    (dir: 1 | -1) => {
      const source = navListRef.current
      const listCodes = source?.getCodes() ?? []
      const usesList = listCodes.includes(code)
      const codes = usesList ? listCodes : globalCodesRef.current
      if (!codes.length) return
      const i = codes.indexOf(code)
      let next: string
      if (i < 0) {
        // 当前代码不在序列中（如从短线精灵/板块指数切入）：按代码插入位就近取
        const pos = codes.findIndex((c) => c > code)
        const j =
          dir > 0
            ? pos < 0
              ? 0
              : pos
            : pos <= 0
              ? codes.length - 1
              : pos - 1
        next = codes[j]
      } else {
        next = codes[(i + dir + codes.length) % codes.length]
      }
      setCode(next)
      if (usesList) source?.revealCode?.(next)
    },
    [code],
  )

  const refresh = useCallback(() => setRefreshTick((value) => value + 1), [])

  // Quote/depth uses MAIN while the unified three-phase intraday request uses
  // the market L2 connection.  Quote/depth starts immediately; intraday gets
  // only a short coalescing window.  The lane gate bounds each lane to the
  // current request plus the latest queued stock.
  useEffect(() => {
    let active = true
    setFast(null)
    setIntraday(null)
    setFastLoading(true)
    // 超级盘口页也内嵌分时图（含大单副图），分时车道全模式开启
    const needsIntraday = true
    setIntradayLoading(needsIntraday)
    setFastError('')
    setIntradayError('')

    const loadFast = async () => {
      const target = code
      const isCurrent = () => active && target === codeRef.current
      if (!isCurrent()) return
      try {
        const firstPaint = await retryCurrentRequest(
          () => api.marketViewFast(target),
          isCurrent,
          (error) => {
            if (!isCurrent()) return
            setFastError(errorText(error))
            setFastLoading(false)
          },
        )
        if (isCurrent()) {
          setFast(firstPaint)
          setFastError('')
        }
      } catch (error) {
        if (isCurrent()) setFastError(errorText(error))
      } finally {
        if (isCurrent()) setFastLoading(false)
      }
    }

    const loadIntraday = async () => {
      const target = code
      const isCurrent = () => active && target === codeRef.current
      if (!isCurrent()) return
      const showRecoverableError = (error: unknown) => {
        if (!isCurrent()) return
        setIntradayError(errorText(error))
        setIntradayLoading(false)
      }
      try {
        // 先完成该股票的 4214 注册，再读取分时；与盘口、逐笔及实时流
        // 共享前端 single-flight，切股时不会同时争抢注册响应。
        await retryCurrentRequest(
          () => api.stockReady(target),
          isCurrent,
          showRecoverableError,
        )
        if (!isCurrent()) return
        const rows = await retryCurrentRequest(
          () => api.intraday(target),
          isCurrent,
          showRecoverableError,
        )
        if (isCurrent()) {
          setIntraday({ code: target, rows })
          setIntradayError('')
        }
      } catch (error) {
        if (isCurrent()) setIntradayError(errorText(error))
      } finally {
        if (isCurrent()) setIntradayLoading(false)
      }
    }

    fastLane(loadFast)
    let timer: ReturnType<typeof setTimeout> | undefined
    if (needsIntraday) {
      timer = setTimeout(() => {
        intradayLane(loadIntraday)
      }, INTRADAY_SWITCH_COALESCE_MS)
    }
    return () => {
      active = false
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [code, mode, refreshTick, fastLane, intradayLane])

  // 集合竞价阶段没有连续交易逐笔推送，分时接口却会持续补充竞价撮合点。
  // 页面若在14:57前打开，单次快照不会自行出现尾盘橙线；只在两个竞价窗口
  // 每3秒刷新当前股票，窗口外不增加任何请求。
  useEffect(() => {
    let active = true
    const startTimers: number[] = []
    const stopTimers: number[] = []
    const intervals: number[] = []

    const poll = () => {
      const target = code
      intradayLane(async () => {
        if (!active || target !== codeRef.current) return
        try {
          await api.stockReady(target)
          if (!active || target !== codeRef.current) return
          const rows = await api.intraday(target)
          if (active && target === codeRef.current) {
            setIntraday({ code: target, rows })
            setIntradayError('')
          }
        } catch (error) {
          if (active && target === codeRef.current) {
            setIntradayError(errorText(error))
          }
        }
      })
    }

    const now = new Date()
    for (const auctionWindow of AUCTION_WINDOWS) {
      const start = new Date(now)
      start.setHours(auctionWindow.start[0], auctionWindow.start[1], 0, 0)
      const end = new Date(now)
      end.setHours(auctionWindow.end[0], auctionWindow.end[1], 0, 0)
      if (now >= end) continue

      const begin = () => {
        if (!active) return
        poll()
        const interval = window.setInterval(poll, AUCTION_POLL_INTERVAL_MS)
        intervals.push(interval)
        stopTimers.push(
          window.setTimeout(
            () => window.clearInterval(interval),
            Math.max(0, end.getTime() - Date.now()),
          ),
        )
      }
      if (now >= start) begin()
      else startTimers.push(window.setTimeout(begin, start.getTime() - now.getTime()))
    }

    return () => {
      active = false
      for (const timer of startTimers) window.clearTimeout(timer)
      for (const timer of stopTimers) window.clearTimeout(timer)
      for (const interval of intervals) window.clearInterval(interval)
    }
  }, [code, mode, intradayLane])

  // K-line starts immediately on the selected market's L2 connection.
  // Period/fuquan changes only rerun this lane.  Cached rows remain visible
  // while the lane refreshes them in the background.
  useEffect(() => {
    if (mode !== 'kanpan') {
      setKlineLoading(false)
      return
    }
    const cacheKey = klineCacheKey(code, period, fuquan)
    const cached = klineCacheRef.current.get(cacheKey)
    if (cached) {
      // Map insertion order is the LRU order; touching moves this entry last.
      klineCacheRef.current.delete(cacheKey)
      klineCacheRef.current.set(cacheKey, cached)
      setKline(cached)
    } else {
      setKline(null)
    }
    setKlineLoading(true)
    setKlineError('')
    let active = true
    const load = async () => {
      const target = code
      const isCurrent = () => active && target === codeRef.current
      if (!isCurrent()) return
      try {
        // KLINE_FAST 也在预热范围内；等它就绪再发，避免与预热争建连。
        await api.preheatReady()
        if (!isCurrent()) return
        // Web 看盘固定复用 Level2 市场连接：沪/北走 SH_L2、深走 SZ_L2，
        // pageid=1334。不要使用 ifindhq_fast；它是独立 BASIC/MAIN 连接。
        const channel = 'level2'
        const rows = await retryCurrentRequest(
          () => api.kline(target, period, 320, fuquan, channel),
          isCurrent,
          (error) => {
            if (!isCurrent()) return
            setKlineError(errorText(error))
            setKlineLoading(false)
          },
        )
        // 展示侧 validKline 还会按 code/period/fuquan 过滤，旧响应不会上屏
        if (isCurrent()) {
          const tagged = { code: target, period, fuquan, rows }
          const targetKey = klineCacheKey(target, period, fuquan)
          klineCacheRef.current.delete(targetKey)
          klineCacheRef.current.set(targetKey, tagged)
          while (klineCacheRef.current.size > KLINE_CACHE_LIMIT) {
            const oldest = klineCacheRef.current.keys().next().value
            if (oldest === undefined) break
            klineCacheRef.current.delete(oldest)
          }
          setKline(tagged)
          setKlineError('')
        }
      } catch (error) {
        if (isCurrent()) setKlineError(errorText(error))
      } finally {
        if (isCurrent()) setKlineLoading(false)
      }
    }
    // 切股时先让轻量盘口和上方分时抢到首屏；快速连续滚动只为最终停留
    // 股票发 K 线，避免每个中间代码都占一次 L2 lane。
    const timer = setTimeout(() => {
      klineLane(load)
    }, KLINE_SWITCH_COALESCE_MS)
    return () => {
      active = false
      clearTimeout(timer)
    }
  }, [code, mode, period, fuquan, refreshTick, klineLane])

  const validFast = fast?.code === code ? fast : null
  const validIntraday = intraday?.code === code ? intraday.rows : null
  const validKline =
    kline?.code === code &&
    kline.period === period &&
    kline.fuquan === fuquan
      ? kline.rows
      : null

  const data = useMemo<MarketView | null>(() => {
    if (!validFast) return null
    return {
      code,
      period,
      fuquan,
      quote: validFast.quote,
      depth: validFast.depth,
      intraday: validIntraday ?? [],
      kline: validKline ?? [],
    }
  }, [code, period, fuquan, validFast, validIntraday, validKline])

  const marketView = useMemo<DataState<MarketView>>(
    () => ({
      data,
      loading: fastLoading,
      error: fastError,
      refresh,
    }),
    [data, fastLoading, fastError, refresh],
  )
  const intradayState = useMemo<DataState<IntradayPoint[]>>(
    () => ({
      data: validIntraday,
      loading: intradayLoading,
      error: intradayError,
      refresh,
    }),
    [validIntraday, intradayLoading, intradayError, refresh],
  )
  const klineState = useMemo<DataState<Kline[]>>(
    () => ({
      data: validKline,
      loading: klineLoading,
      error: klineError,
      refresh,
    }),
    [validKline, klineLoading, klineError, refresh],
  )

  const q = validFast?.quote
  const quote = useMemo<QuoteInfo | null>(() => {
    if (!q) return null
    const dailyRows =
      period === 'day'
        ? validKline
        : klineCacheRef.current.get(klineCacheKey(code, 'day', fuquan))?.rows
    const todayBar = dailyRows?.[dailyRows.length - 1]
    const price = q.dt10
    const prevClose = q.dt6
    const chg = price != null && prevClose != null ? price - prevClose : undefined
    const chgPct = chg != null && prevClose ? (chg / prevClose) * 100 : undefined
    return {
      price,
      prevClose,
      open: q.dt7 ?? todayBar?.open,
      high: q.dt8 ?? todayBar?.high,
      low: q.dt9 ?? todayBar?.low,
      vol: q.dt13,
      amount: q.dt19 ?? todayBar?.amount,
      chg,
      chgPct,
    }
  }, [q, code, period, fuquan, validKline])

  return (
    <Ctx.Provider
      value={{
        code,
        setCode: setCodeWithSource,
        period,
        setPeriod,
        fuquan,
        setFuquan,
        quote,
        marketView,
        intradayState,
        klineState,
        navigate,
        globalCodesRef,
      }}
    >
      {children}
    </Ctx.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export const useStock = () => useContext(Ctx)
