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

/** 列表导航源：getCodes 返回该列表“当前”的完整代码顺序（点击后排序变化也跟随） */
export interface StockNavSource {
  getCodes: () => string[]
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
  klineState: emptyKline,
  navigate: () => {},
  globalCodesRef: { current: [] },
})

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
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

export function StockProvider({ children }: { children: ReactNode }) {
  const [code, setCode] = useState('600519')
  const [period, setPeriod] = useState<KlinePeriod>('day')
  const [fuquan, setFuquan] = useState('Q')
  const [fast, setFast] = useState<MarketViewFast | null>(null)
  const [intraday, setIntraday] = useState<{
    code: string
    rows: IntradayPoint[]
  } | null>(null)
  const [kline, setKline] = useState<TaggedKline | null>(null)
  const [fastLoading, setFastLoading] = useState(true)
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
  // 键盘/滚轮切换股票：最近点击的列表（顺序源）+ 全市场代码（升序回退）
  const navListRef = useRef<StockNavSource | null>(null)
  const globalCodesRef = useRef<string[]>([])

  const setCodeWithSource = useCallback(
    (next: string, source?: StockNavSource) => {
      if (source) navListRef.current = source
      setCode(next)
    },
    [],
  )

  const navigate = useCallback(
    (dir: 1 | -1) => {
      const listCodes = navListRef.current?.getCodes() ?? []
      const codes = listCodes.includes(code)
        ? listCodes
        : globalCodesRef.current
      if (!codes.length) return
      const i = codes.indexOf(code)
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
        setCode(codes[j])
        return
      }
      setCode(codes[(i + dir + codes.length) % codes.length])
    },
    [code],
  )

  const refresh = useCallback(() => setRefreshTick((value) => value + 1), [])

  // Quote/depth and the unified three-phase intraday request use independent
  // connections.  Start both immediately and let each dataset paint as soon
  // as it arrives; market_view_fast deliberately contains no timeline rows.
  // 快速连切合并：防抖 + 通道闸门（在途最多 1 个，中间代码不占 socket）。
  useEffect(() => {
    setFast(null)
    setIntraday(null)
    setFastLoading(true)
    setFastError('')
    setIntradayError('')

    const loadFast = async () => {
      const target = codeRef.current
      try {
        const firstPaint = await api.marketViewFast(target)
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
        const rows = await api.intraday(target)
        if (target === codeRef.current) setIntraday({ code: target, rows })
      } catch (error) {
        if (target === codeRef.current) setIntradayError(errorText(error))
      }
    }

    // 防抖窗口 > 滚轮节流档(120ms)：持续滚动/按住方向键期间完全不发请求，
    // 停下后一次拉最终代码；闸门再保证在途最多 1 个。
    const FAST_DEBOUNCE_MS = 150
    const timer = setTimeout(() => {
      fastLane(loadFast)
      intradayLane(loadIntraday)
    }, FAST_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [code, refreshTick, fastLane, intradayLane])

  // K-line has its own ifindhq socket and starts alongside the two requests
  // above.  Period/fuquan changes only rerun this lane.  同样走闸门：连切时
  // 最多 1 个在途 K 线请求。
  useEffect(() => {
    setKline(null)
    setKlineLoading(true)
    setKlineError('')
    const load = async () => {
      const target = codeRef.current
      try {
        // KLINE_FAST 也在预热范围内；等它就绪再发，避免与预热争建连。
        await api.preheatReady()
        if (target !== codeRef.current) return
        // 北交所走后端 auto：Level2 账号会在 shlv2 上用 pageid=1334 查 K线
        // （与 2026-08-15 客户端抓包一致）；沪深继续用独立 ifindhq_fast 通道。
        const channel =
          target.startsWith('920') ||
          target.startsWith('43') ||
          target.startsWith('83') ||
          target.startsWith('87')
            ? 'auto'
            : 'ifindhq_fast'
        const rows = await api.kline(target, period, 320, fuquan, channel)
        // 展示侧 validKline 还会按 code/period/fuquan 过滤，旧响应不会上屏
        if (target === codeRef.current) {
          setKline({ code: target, period, fuquan, rows })
        }
      } catch (error) {
        if (target === codeRef.current) setKlineError(errorText(error))
      } finally {
        if (target === codeRef.current) setKlineLoading(false)
      }
    }
    // K 线延迟约 40ms 发出：合并连续切股（闸门再兜底堵 socket 队列）。
    const KLINE_DEBOUNCE_MS = 40
    const timer = setTimeout(() => klineLane(load), KLINE_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [code, period, fuquan, refreshTick, klineLane])

  const validFast = fast?.code === code ? fast : null
  const validIntraday = intraday?.code === code ? intraday.rows : []
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
      intraday: validIntraday,
      kline: validKline ?? [],
    }
  }, [code, period, fuquan, validFast, validIntraday, validKline])

  const marketView = useMemo<DataState<MarketView>>(
    () => ({
      data,
      loading: fastLoading,
      error: [fastError, intradayError].filter(Boolean).join('; '),
      refresh,
    }),
    [data, fastLoading, fastError, intradayError, refresh],
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
    const price = q.dt10
    const prevClose = q.dt6
    const chg = price != null && prevClose != null ? price - prevClose : undefined
    const chgPct = chg != null && prevClose ? (chg / prevClose) * 100 : undefined
    return {
      price,
      prevClose,
      open: q.dt7,
      high: q.dt8,
      low: q.dt9,
      vol: q.dt13,
      amount: q.dt19,
      chg,
      chgPct,
    }
  }, [q])

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
