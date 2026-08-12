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

interface StockCtx {
  code: string
  setCode: (code: string) => void
  period: KlinePeriod
  setPeriod: (period: KlinePeriod) => void
  fuquan: string
  setFuquan: (fuquan: string) => void
  quote: QuoteInfo | null
  marketView: DataState<MarketView>
  klineState: DataState<Kline[]>
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
})

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
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
  const marketGeneration = useRef(0)
  const klineGeneration = useRef(0)

  const refresh = useCallback(() => setRefreshTick((value) => value + 1), [])

  // Quote/depth and the unified three-phase intraday request use independent
  // connections.  Start both immediately and let each dataset paint as soon
  // as it arrives; market_view_fast deliberately contains no timeline rows.
  useEffect(() => {
    const requestGeneration = ++marketGeneration.current
    let alive = true
    setFast(null)
    setIntraday(null)
    setFastLoading(true)
    setFastError('')
    setIntradayError('')

    const loadFast = async () => {
      try {
        const firstPaint = await api.marketViewFast(code)
        if (!alive || marketGeneration.current !== requestGeneration) return
        setFast(firstPaint)
      } catch (error) {
        if (!alive || marketGeneration.current !== requestGeneration) return
        setFastError(errorText(error))
      } finally {
        if (alive && marketGeneration.current === requestGeneration) {
          setFastLoading(false)
        }
      }
    }

    const loadIntraday = async () => {
      try {
        const rows = await api.intraday(code)
        if (!alive || marketGeneration.current !== requestGeneration) return
        setIntraday({ code, rows })
      } catch (error) {
        if (!alive || marketGeneration.current !== requestGeneration) return
        setIntradayError(errorText(error))
      }
    }

    void loadFast()
    void loadIntraday()
    return () => {
      alive = false
    }
  }, [code, refreshTick])

  // K-line has its own ifindhq socket and starts alongside the two requests
  // above.  Period/fuquan changes only rerun this lane.
  useEffect(() => {
    const requestGeneration = ++klineGeneration.current
    let alive = true
    setKline(null)
    setKlineLoading(true)
    setKlineError('')
    const load = async () => {
      try {
        const rows = await api.kline(
          code,
          period,
          320,
          fuquan,
          'ifindhq_fast',
        )
        if (!alive || klineGeneration.current !== requestGeneration) return
        setKline({ code, period, fuquan, rows })
      } catch (error) {
        if (!alive || klineGeneration.current !== requestGeneration) return
        setKlineError(errorText(error))
      } finally {
        if (alive && klineGeneration.current === requestGeneration) {
          setKlineLoading(false)
        }
      }
    }
    void load()
    return () => {
      alive = false
    }
  }, [code, period, fuquan, refreshTick])

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
        setCode,
        period,
        setPeriod,
        fuquan,
        setFuquan,
        quote,
        marketView,
        klineState,
      }}
    >
      {children}
    </Ctx.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export const useStock = () => useContext(Ctx)
