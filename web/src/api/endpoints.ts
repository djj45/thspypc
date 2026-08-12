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
  Dxjl,
  StockGroup,
  MarketView,
  MarketViewFast,
} from '../types'

const marketViewInFlight = new Map<string, Promise<MarketView>>()
const fastViewInFlight = new Map<string, Promise<MarketViewFast>>()
const intradayInFlight = new Map<
  string,
  Promise<(AuctionPoint & TimelinePoint)[]>
>()
const klineInFlight = new Map<string, Promise<Kline[]>>()

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
    return dedupe(klineInFlight, key, () =>
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
    dedupe(intradayInFlight, code, () =>
      getJson<(AuctionPoint & TimelinePoint)[]>(`/api/intraday/${code}`),
    ),
  marketView: (code: string, period = 'day', count = 320, fuquan = 'Q') =>
    getMarketView(code, period, count, fuquan),
  marketViewFast: (code: string) =>
    dedupe(fastViewInFlight, code, () =>
      getJson<MarketViewFast>(`/api/market_view_fast/${code}`),
    ),
  intradayAuctions: (code: string) =>
    dedupe(intradayInFlight, `auctions|${code}`, () =>
      getJson<(AuctionPoint & TimelinePoint)[]>(
        `/api/intraday_auctions/${code}`,
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
  stockListRanked: (sortBy: number, count = 59, withValues = false) =>
    getJson<RankItem[]>(
      `/api/stock_list_ranked?sort_by=${sortBy}&count=${count}&sort_dir=D&with_values=${withValues ? 1 : 0}`,
    ),
  ddeRank: (sortBy = 592888, count = 58) =>
    getJson<RankItem[]>(`/api/dde_rank?sort_by=${sortBy}&count=${count}`),

  // 自选 / 自定义板块 / 动态板块
  groups: () => getJson<StockGroup[]>('/api/groups'),
  group: (name: string) => getJson<StockGroup>(`/api/groups/${name}`),
  selfStocks: () => getJson<StockGroup>('/api/self_stocks'),
  dynamicPlates: () =>
    getJson<Record<string, string[]>>('/api/dynamic_plates'),

  // 短线精灵
  dxjlLatest: () => getJson<Dxjl[]>('/api/dxjl/latest'),
  dxjlHistory: (pages = 5) => getJson<Dxjl[]>(`/api/dxjl?pages=${pages}`),
}
