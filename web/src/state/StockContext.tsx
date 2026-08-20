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

export const KLINE_PERIODS = [
  'day',
  'week',
  'month',
  '60',
  '30',
  '15',
  '5',
  '1',
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

function isRecoverableRequestError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === 'TimeoutError' ||
      /signal timed out|failed to fetch|HTTP 502/i.test(error.message))
  )
}

// 只恢复最终停留的股票。后端 Web 路由会把单次协议工作限制在浏览器超时以内，
// 这里再用退避处理短暂的 502/网络超时；已经切走的旧任务绝不重试。
async function retryCurrentRequest<T>(
  request: () => Promise<T>,
  isCurrent: () => boolean,
): Promise<T> {
  const retryDelays = [1_500, 4_000]
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await request()
    } catch (error) {
      if (
        attempt >= retryDelays.length ||
        !isRecoverableRequestError(error) ||
        !isCurrent()
      ) {
        throw error
      }
      await new Promise((resolve) =>
        setTimeout(resolve, retryDelays[attempt]),
      )
      if (!isCurrent()) throw error
    }
  }
}

// 盘口和 K 线用于首屏，切股后立即发起。分时返回更大，且与 K 线
// 共用市场 L2 socket，只保留一个人无感的短合并窗口。
const INTRADAY_SWITCH_COALESCE_MS = 100
const KLINE_SWITCH_COALESCE_MS = 180

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
    setFast(null)
    setIntraday(null)
    setFastLoading(true)
    const needsIntraday = mode !== 'superorder'
    setIntradayLoading(needsIntraday)
    setFastError('')
    setIntradayError('')

    const loadFast = async () => {
      const target = codeRef.current
      try {
        const firstPaint = await retryCurrentRequest(
          () => api.marketViewFast(target),
          () => target === codeRef.current,
        )
        if (target === codeRef.current) {
          setFast(firstPaint)
          setFastError('')
        }
      } catch (error) {
        if (target === codeRef.current) setFastError(errorText(error))
      } finally {
        if (target === codeRef.current) setFastLoading(false)
      }
    }

    const loadIntraday = async () => {
      const target = codeRef.current
      try {
        // 等待后端预热就绪再走 L2，避免冷启动时请求排队等锁/超时。
        await api.preheatReady()
        if (target !== codeRef.current) return
        const rows = await retryCurrentRequest(
          () => api.intraday(target),
          () => target === codeRef.current,
        )
        if (target === codeRef.current) setIntraday({ code: target, rows })
      } catch (error) {
        if (target === codeRef.current) setIntradayError(errorText(error))
      } finally {
        if (target === codeRef.current) setIntradayLoading(false)
      }
    }

    fastLane(loadFast)
    if (!needsIntraday) return
    const timer = setTimeout(() => {
      intradayLane(loadIntraday)
    }, INTRADAY_SWITCH_COALESCE_MS)
    return () => clearTimeout(timer)
  }, [code, mode, refreshTick, fastLane, intradayLane])

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
    const load = async () => {
      const target = codeRef.current
      try {
        // KLINE_FAST 也在预热范围内；等它就绪再发，避免与预热争建连。
        await api.preheatReady()
        if (target !== codeRef.current) return
        // Web 看盘固定复用 Level2 市场连接：沪/北走 SH_L2、深走 SZ_L2，
        // pageid=1334。不要使用 ifindhq_fast；它是独立 BASIC/MAIN 连接。
        const channel = 'level2'
        const rows = await retryCurrentRequest(
          () => api.kline(target, period, 320, fuquan, channel),
          () => target === codeRef.current,
        )
        // 展示侧 validKline 还会按 code/period/fuquan 过滤，旧响应不会上屏
        if (target === codeRef.current) {
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
        }
      } catch (error) {
        if (target === codeRef.current) setKlineError(errorText(error))
      } finally {
        if (target === codeRef.current) setKlineLoading(false)
      }
    }
    // 切股时先让轻量盘口和上方分时抢到首屏；快速连续滚动只为最终停留
    // 股票发 K 线，避免每个中间代码都占一次 L2 lane。
    const timer = setTimeout(() => {
      klineLane(load)
    }, KLINE_SWITCH_COALESCE_MS)
    return () => clearTimeout(timer)
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
