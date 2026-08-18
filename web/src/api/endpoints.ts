import { getJson, postJson } from './client'
import type {
  Status,
  Quote,
  Depth,
  Kline,
  TimelinePoint,
  AuctionPoint,
  Board,
  BoardCategory,
  SystemBlock,
  RankItem,
  StockListItem,
  QuoteExt,
  Dxjl,
  StockGroup,
  DynamicPlate,
  MarketView,
  MarketViewFast,
} from '../types'

const marketViewInFlight = new Map<string, Promise<MarketView>>()
const fastViewInFlight = new Map<string, Promise<MarketViewFast>>()
const quotesExtInFlight = new Map<string, Promise<QuoteExt[]>>()
const intradayInFlight = new Map<
  string,
  Promise<(AuctionPoint & TimelinePoint)[]>
>()
const klineInFlight = new Map<string, Promise<Kline[]>>()

// 已返回结果的短 TTL 缓存：快速来回切票/刷新时不再重复请求。
// 分时/盘口缓存秒级；日 K 稍长（下一根 K 更新前基本不变）。
const FAST_VIEW_TTL_MS = 1_000
const INTRADAY_TTL_MS = 2_000
const KLINE_DAY_TTL_MS = 15_000
const KLINE_MINUTE_TTL_MS = 3_000
const CACHE_LIMIT = 64

interface CacheEntry<T> {
  at: number
  value: T
}

const fastViewCache = new Map<string, CacheEntry<MarketViewFast>>()
const intradayCache = new Map<string, CacheEntry<(AuctionPoint & TimelinePoint)[]>>()
const klineCache = new Map<string, CacheEntry<Kline[]>>()

function trimCache<T>(cache: Map<string, CacheEntry<T>>): void {
  if (cache.size <= CACHE_LIMIT) return
  let oldestKey: string | undefined
  let oldestAt = Number.POSITIVE_INFINITY
  for (const [key, entry] of cache) {
    if (entry.at < oldestAt) {
      oldestAt = entry.at
      oldestKey = key
    }
  }
  if (oldestKey !== undefined) cache.delete(oldestKey)
}

function ttlCached<T>(
  cache: Map<string, CacheEntry<T>>,
  inflight: Map<string, Promise<T>>,
  key: string,
  ttlMs: number,
  fetcher: () => Promise<T>,
): Promise<T> {
  const hit = cache.get(key)
  if (hit && Date.now() - hit.at < ttlMs) return Promise.resolve(hit.value)
  const current = inflight.get(key)
  if (current) return current
  const request = fetcher()
    .then((value) => {
      cache.set(key, { at: Date.now(), value })
      trimCache(cache)
      return value
    })
    .finally(() => inflight.delete(key))
  inflight.set(key, request)
  return request
}

function dedupe<T>(
  requests: Map<string, Promise<T>>,
  key: string,
  fetcher: () => Promise<T>,
): Promise<T> {
  const current = requests.get(key)
  if (current) return current
  const request = fetcher().finally(() => requests.delete(key))
  requests.set(key, request)
  return request
}

// 后端预热完成前，K线/分时先在浏览器侧等待，避免与预热抢锁/超时；
// 盘口（MAIN）不需要等待，仍立即发出保证首屏。
let preheatReadyPromise: Promise<void> | null = null
function waitForPreheat(): Promise<void> {
  if (preheatReadyPromise) return preheatReadyPromise
  const polling = (async () => {
    const deadline = Date.now() + 20_000
    while (Date.now() < deadline) {
      try {
        const status = await getJson<Status>('/api/status')
        const state = status.preheat?.state
        // ready/skipped=可安全发请求；partial/error=继续等只会让页面一直卡住，
        // 直接放行由各接口自身报错或成功。
        if (state === 'ready' || state === 'skipped' || state === 'partial' || state === 'error') {
          return
        }
        if (!status.preheat && status.connected) return
      } catch {
        // 后端暂时不可达：直接放行，让业务请求暴露具体错误。
        return
      }
      await new Promise((resolve) => setTimeout(resolve, 250))
    }
  })()
  preheatReadyPromise = polling
  // 下次切换/刷新重新检查状态，后端单独重启时不会一直复用旧的 resolved 结果。
  void polling.finally(() => {
    preheatReadyPromise = null
  })
  return polling
}

function getMarketView(
  code: string,
  period: string,
  count: number,
  fuquan: string,
): Promise<MarketView> {
  const key = `${code}|${period}|${count}|${fuquan}`
  const current = marketViewInFlight.get(key)
  if (current) return current
  const request = getJson<MarketView>(
    `/api/market_view/${code}?period=${period}&count=${count}&fuquan=${encodeURIComponent(fuquan)}`,
  ).finally(() => marketViewInFlight.delete(key))
  marketViewInFlight.set(key, request)
  return request
}

// 市场码：0 让后端按代码前缀自推断（支持 沪/深/指数/北交所）
export const api = {
  // 连接
  status: () => getJson<Status>('/api/status'),
  preheatReady: () => waitForPreheat(),
  connect: () =>
    postJson<{ success: boolean; server: string; error: string }>('/api/connect'),

  // 单股行情 / 盘口 / K线 / 分时
  quote: (codes: string[]) =>
    getJson<Quote[]>(`/api/quote?codes=${codes.join(',')}`),
  depth: (code: string, levels: 5 | 10 = 5) =>
    getJson<Depth>(`/api/depth/${code}?levels=${levels}`),
  kline: (
    code: string,
    period = 'day',
    count = 2146,
    fuquan = 'Q',
    channel: 'auto' | 'level2' | 'ifindhq_fast' = 'auto',
  ) => {
    const key = `${code}|${period}|${count}|${fuquan}|${channel}`
    const ttl =
      period === 'day' || period === 'week' || period === 'month'
        ? KLINE_DAY_TTL_MS
        : KLINE_MINUTE_TTL_MS
    return ttlCached(klineCache, klineInFlight, key, ttl, () =>
      getJson<Kline[]>(
        `/api/kline/${code}?period=${period}&count=${count}&fuquan=${encodeURIComponent(fuquan)}&channel=${channel}`,
      ),
    )
  },
  timeline: (code: string) => getJson<TimelinePoint[]>(`/api/timeline/${code}`),
  historyTimeline: (code: string, date: string) =>
    getJson<TimelinePoint[]>(`/api/history_timeline/${code}?date=${date}`),
  auction: (code: string) => getJson<AuctionPoint[]>(`/api/auction/${code}`),
  closingAuction: (code: string) =>
    getJson<AuctionPoint[]>(`/api/closing_auction/${code}`),
  intraday: (code: string) =>
    ttlCached(intradayCache, intradayInFlight, code, INTRADAY_TTL_MS, () =>
      getJson<(AuctionPoint & TimelinePoint)[]>(`/api/intraday/${code}`),
    ),
  marketView: (code: string, period = 'day', count = 320, fuquan = 'Q') =>
    getMarketView(code, period, count, fuquan),
  marketViewFast: (code: string) =>
    ttlCached(fastViewCache, fastViewInFlight, code, FAST_VIEW_TTL_MS, () =>
      getJson<MarketViewFast>(`/api/market_view_fast/${code}`),
    ),
  intradayAuctions: (code: string) =>
    dedupe(intradayInFlight, `auctions|${code}`, () =>
      getJson<(AuctionPoint & TimelinePoint)[]>(
        `/api/intraday_auctions/${code}`,
      ),
    ),

  // 全市场代码表（磁盘缓存，自然日有效；供左栏名称回填）
  stocks2: () => getJson<StockListItem[]>('/api/stocks2'),

  // 统一列表字段（涨幅/竞价涨幅/竞价金额/成交额/4分钟涨速，按代码批量）
  quotesExt: (codes: string[]) =>
    dedupe(
      quotesExtInFlight,
      codes.join(','),
      () =>
        getJson<QuoteExt[]>(
          `/api/quotes_ext?codes=${encodeURIComponent(codes.join(','))}`,
        ),
    ),

  // 板块
  boardCategories: () => getJson<BoardCategory[]>('/api/board_categories'),
  boards: (category?: string) =>
    getJson<SystemBlock[]>(
      category ? `/api/boards?category=${category}` : '/api/boards',
    ),
  hotBoards: () => getJson<Board[]>('/api/hot_boards'),

  // 排序榜
  stockListRanked: (
    sortBy: number,
    count = 59,
    withValues = false,
    sortDir: 'D' | 'A' = 'D',
  ) =>
    getJson<RankItem[]>(
      `/api/stock_list_ranked?sort_by=${sortBy}&count=${count}&sort_dir=${sortDir}&with_values=${withValues ? 1 : 0}`,
    ),
  ddeRank: (sortBy = 592888, count = 58) =>
    getJson<RankItem[]>(`/api/dde_rank?sort_by=${sortBy}&count=${count}`),

  // 自选 / 自定义板块 / 动态板块
  groups: () => getJson<StockGroup[]>('/api/groups'),
  group: (name: string) => getJson<StockGroup>(`/api/groups/${name}`),
  selfStocks: () => getJson<StockGroup>('/api/self_stocks'),
  dynamicPlates: () => getJson<DynamicPlate[]>('/api/dynamic_plates'),
  dynamicPlateRefresh: (name: string) =>
    getJson<DynamicPlate>(
      `/api/dynamic_plate_refresh?name=${encodeURIComponent(name)}`,
    ),

  // 短线精灵
  dxjlLatest: () => getJson<Dxjl[]>('/api/dxjl/latest'),
  dxjlHistory: (pages = 5) => getJson<Dxjl[]>(`/api/dxjl?pages=${pages}`),
}
