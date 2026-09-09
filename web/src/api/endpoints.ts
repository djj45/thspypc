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
  OrderQueues,
  ReplayIndex,
  ReplaySnapshot,
  SuperorderWindow,
  MarketEvent,
  BseTick,
  BseSuperorderRow,
} from '../types'

// 市场码推断（与后端 _market_for_code 对齐）：0 让后端按代码前缀自推断
// （支持 沪/深/指数/北交所）。北交所个股（43/83/87/920 前缀）= 151。
export function marketOfCode(code: string): number {
  if (code.startsWith('1A') || code.startsWith('1B')) return 16
  if (code.startsWith('39')) return 32
  if (code.startsWith('899')) return 144
  if (code.startsWith('43') || code.startsWith('83') || code.startsWith('87') || code.startsWith('920')) return 151
  if (code.startsWith('6')) return 17
  return 33
}

export const isBseCode = (code: string): boolean => marketOfCode(code) === 151

function pad2(part: number): string {
  return String(part).padStart(2, '0')
}

// unix 秒 → 本地 ISO 秒串（/api/superorder 的 start/end 参数格式）。
// 与 SuperorderPage 的 localIso 同一约定：浏览器本地时区 = 交易所时区。
export function tsToLocalIso(ts: number): string {
  const value = new Date(ts * 1000)
  return (
    `${value.getFullYear()}-${pad2(value.getMonth() + 1)}-${pad2(value.getDate())}` +
    `T${pad2(value.getHours())}:${pad2(value.getMinutes())}:${pad2(value.getSeconds())}`
  )
}

const marketViewInFlight = new Map<string, Promise<MarketView>>()
const fastViewInFlight = new Map<string, Promise<MarketViewFast>>()
const quotesExtInFlight = new Map<string, Promise<QuoteExt[]>>()
const rankInFlight = new Map<string, Promise<RankItem[]>>()
const intradayInFlight = new Map<
  string,
  Promise<(AuctionPoint & TimelinePoint)[]>
>()
const klineInFlight = new Map<string, Promise<Kline[]>>()
const stockReadyInFlight = new Map<string, Promise<void>>()
const stockReadyUntil = new Map<string, number>()
const groupsInFlight = new Map<string, Promise<StockGroup[]>>()
const dynamicPlatesInFlight = new Map<string, Promise<DynamicPlate[]>>()
const selfStocksInFlight = new Map<string, Promise<StockGroup>>()
const boardConstituentsInFlight = new Map<string, Promise<Quote[]>>()
const boardKlineInFlight = new Map<string, Promise<Kline[]>>()

// 已返回结果的短 TTL 缓存：快速来回切票/刷新时不再重复请求。
// 分时/盘口缓存秒级；日 K 稍长（下一根 K 更新前基本不变）。
const FAST_VIEW_TTL_MS = 1_000
const INTRADAY_TTL_MS = 2_000
const KLINE_DAY_TTL_MS = 15_000
const KLINE_MINUTE_TTL_MS = 3_000
const CACHE_LIMIT = 64
const STOCK_READY_TTL_MS = 2_000

interface CacheEntry<T> {
  at: number
  value: T
}

const fastViewCache = new Map<string, CacheEntry<MarketViewFast>>()
const quotesExtCache = new Map<string, CacheEntry<QuoteExt[]>>()
const intradayCache = new Map<string, CacheEntry<(AuctionPoint & TimelinePoint)[]>>()
const klineCache = new Map<string, CacheEntry<Kline[]>>()
const boardKlineCache = new Map<string, CacheEntry<Kline[]>>()

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
let preheatReadyUntil = 0
function waitForPreheat(): Promise<void> {
  if (Date.now() < preheatReadyUntil) return Promise.resolve()
  if (preheatReadyPromise) return preheatReadyPromise
  let reachedTerminalState = false
  const polling = (async () => {
    const deadline = Date.now() + 20_000
    while (Date.now() < deadline) {
      try {
        const status = await getJson<Status>('/api/status')
        const state = status.preheat?.state
        // connected 只表示 MAIN 已登录；此时后台可能仍在并行预建 SH/SZ
        // L2。若立即由页面再懒建同一市场连接，会同时消费两代 Passport，
        // 偶发 VerifyCode=-1。必须等预热终态后再开放 L2 页面请求。
        // ready/skipped=可安全发请求；partial/error=继续等只会让页面一直卡住，
        // 直接放行，由各接口复用已成功的角色或按需补建失败角色。
        if (state === 'ready' || state === 'skipped' || state === 'partial' || state === 'error') {
          reachedTerminalState = true
          return
        }
      } catch {
        // 后端暂时不可达：直接放行，让业务请求暴露具体错误。
        return
      }
      await new Promise((resolve) => setTimeout(resolve, 250))
    }
  })()
  preheatReadyPromise = polling
  // 快速切股期间复用终态，避免每只股票重复 /api/status；30 秒后重查，
  // 后端单独重启时也不会长期复用旧状态。
  void polling.finally(() => {
    if (reachedTerminalState) preheatReadyUntil = Date.now() + 30_000
    preheatReadyPromise = null
  })
  return polling
}

function waitForStockReady(code: string): Promise<void> {
  const now = Date.now()
  if ((stockReadyUntil.get(code) ?? 0) > now) return Promise.resolve()
  const current = stockReadyInFlight.get(code)
  if (current) return current
  const request = waitForPreheat()
    .then(() => getJson<{ code: string; market: number; ready: boolean }>(
      `/api/stock-ready/${code}`,
      20_000,
    ))
    .then(() => {
      stockReadyUntil.set(code, Date.now() + STOCK_READY_TTL_MS)
    })
    .finally(() => stockReadyInFlight.delete(code))
  stockReadyInFlight.set(code, request)
  return request
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
  stockReady: (code: string) => waitForStockReady(code),
  connect: () =>
    postJson<{ success: boolean; server: string; error: string }>('/api/connect'),

  // 单股行情 / 盘口 / K线 / 分时
  quote: (codes: string[]) =>
    getJson<Quote[]>(`/api/quote?codes=${codes.join(',')}`),
  depth: (code: string, levels: 5 | 10 = 5) =>
    getJson<Depth>(
      `/api/depth/${code}?levels=${levels}`,
      levels === 10 ? 20_000 : 6_000,
    ),
  kline: (
    code: string,
    period = 'day',
    count = 2146,
    fuquan = 'Q',
    channel: 'auto' | 'level2' | 'ifindhq_fast' = 'auto',
  ) => {
    const key = `${code}|${period}|${count}|${fuquan}|${channel}`
    const ttl =
      period === 'day' ||
      period === 'week' ||
      period === 'month' ||
      period === 'quarter' ||
      period === 'year'
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
      getJson<(AuctionPoint & TimelinePoint)[]>(
        `/api/intraday/${code}`,
        20_000,
      ),
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
  orderQueues: (code: string, tradeDate?: string) =>
    getJson<OrderQueues>(
      `/api/order-queues/${code}${tradeDate ? `?trade_date=${encodeURIComponent(tradeDate)}` : ''}`,
      60_000,
    ),
  superorderReplay: (code: string, tradeDate?: string) =>
    getJson<ReplayIndex>(
      `/api/superorder-replay/${code}${tradeDate ? `?trade_date=${encodeURIComponent(tradeDate)}` : ''}`,
      90_000,
    ),
  superorderSnapshot: (code: string, ts: number, tradeDate?: string) =>
    getJson<ReplaySnapshot>(
      `/api/superorder-replay/${code}/snapshot?ts=${ts}${tradeDate ? `&trade_date=${encodeURIComponent(tradeDate)}` : ''}`,
      40_000,
    ),
  superorderWindow: (code: string, start: string, end: string) =>
    getJson<SuperorderWindow>(
      `/api/superorder-window/${code}?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`,
      60_000,
    ),
  superorderTrades: (code: string, start: string, end: string) =>
    getJson<MarketEvent[]>(
      `/api/superorder/${code}?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}&pageid=4214`,
      25_000,
    ),
  // 北交所 7176 竞价逐笔窗口（09:15-09:25，恰 600s——更短窗口服务端不回
  // 数据，且连续竞价时段无逐笔通道，2026-09-08 活网验证）。timeout=6s：
  // 非交易日/无成交窗口要么被服务端以 0 行表确认，要么快速失败。
  superorderBseWindow: (code: string, startTs: number, endTs: number) =>
    getJson<BseTick[]>(
      `/api/superorder/${code}?start=${encodeURIComponent(tsToLocalIso(startTs))}&end=${encodeURIComponent(tsToLocalIso(endTs))}&timeout=6`,
      9_000,
    ),
  // 北交所当日超级盘口（1207 页 4096 全日窗）：逐笔 + 五档快照，仅当日。
  // timeout=8s：非交易日服务端不回数据，快速失败后走竞价窗兜底。
  superorderBseDay: (code: string) =>
    getJson<BseSuperorderRow[]>(
      `/api/superorder-bse/${code}?timeout=8`,
      12_000,
    ),
  // 指定交易日的完整日内序列（超级盘口页北交所历史日期取竞价逐笔用）。
  intradayDated: (code: string, tradeDate: string) =>
    getJson<(AuctionPoint & TimelinePoint)[]>(
      `/api/intraday/${code}?trade_date=${encodeURIComponent(tradeDate)}`,
      20_000,
    ),
  stockStreamUrl: (code: string) => {
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
    return `${scheme}://${window.location.host}/api/stock-stream/${code}?market=${marketOfCode(code)}`
  },

  dxjlStreamUrl: () => {
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
    return `${scheme}://${window.location.host}/api/dxjl/stream`
  },

  // 全市场代码表（磁盘缓存，自然日有效；供左栏名称回填）
  stocks2: () => getJson<StockListItem[]>('/api/stocks2'),

  // 统一列表字段（涨幅/竞价涨幅/竞价金额/成交额/4分钟涨速，按代码批量）
  quotesExt: (codes: string[]) =>
    ttlCached(
      quotesExtCache,
      quotesExtInFlight,
      codes.join(','),
      3_000,
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

  // 94板块页：成分股（fu4 批量行情，慢路径 45s）、板块分时、板块日K
  boardConstituents: (code: string) =>
    dedupe(boardConstituentsInFlight, code, () =>
      getJson<Quote[]>(`/api/board/${code}/constituents`, 45_000),
    ),
  boardTimeline: (code: string) =>
    getJson<TimelinePoint[]>(`/api/board/${code}/timeline`, 20_000),
  boardKline: (code: string, count = 320, fuquan = 'Q') =>
    ttlCached(
      boardKlineCache,
      boardKlineInFlight,
      `${code}|${count}|${fuquan}`,
      KLINE_DAY_TTL_MS,
      () =>
        getJson<Kline[]>(
          `/api/board/${code}/kline?count=${count}&fuquan=${encodeURIComponent(fuquan)}`,
          20_000,
        ),
    ),

  // 排序榜
  stockListRanked: (
    sortBy: number,
    count = 59,
    withValues = false,
    sortDir: 'D' | 'A' = 'D',
  ) => {
    const key = `${sortBy}|${count}|${sortDir}|${withValues ? 1 : 0}`
    return dedupe(rankInFlight, key, () =>
      // 5400 条全市场榜在冷启动时会排在 K线/分时的同市场 L2 lane 后面。
      // 服务端正常完成并返回 200 仍可能超过轻量接口统一的 6s 预算，因此大榜
      // 使用独立的 30s 上限；相同参数在 React 重挂载时只保留一个在途请求。
      getJson<RankItem[]>(
        `/api/stock_list_ranked?sort_by=${sortBy}&count=${count}&sort_dir=${sortDir}&with_values=${withValues ? 1 : 0}`,
        count > 1000 ? 30_000 : 10_000,
      ),
    )
  },
  ddeRank: (sortBy = 592888, count = 58) =>
    getJson<RankItem[]>(`/api/dde_rank?sort_by=${sortBy}&count=${count}`),

  // 自选 / 自定义板块 / 动态板块
  groups: () =>
    dedupe(groupsInFlight, 'groups', () =>
      getJson<StockGroup[]>('/api/groups'),
    ),
  group: (name: string) => getJson<StockGroup>(`/api/groups/${name}`),
  selfStocks: () =>
    dedupe(selfStocksInFlight, 'self', () =>
      getJson<StockGroup>('/api/self_stocks'),
    ),
  dynamicPlates: () =>
    dedupe(dynamicPlatesInFlight, 'plates', () =>
      getJson<DynamicPlate[]>('/api/dynamic_plates'),
    ),
  dynamicPlateRefresh: (name: string) =>
    getJson<DynamicPlate>(
      `/api/dynamic_plate_refresh?name=${encodeURIComponent(name)}`,
    ),

  // 短线精灵
  dxjlLatest: () => getJson<Dxjl[]>('/api/dxjl/latest'),
  dxjlHistory: (pages = 5, endtime?: number) =>
    getJson<Dxjl[]>(
      `/api/dxjl?pages=${pages}${endtime != null ? `&endtime=${endtime}` : ''}`,
    ),
}
