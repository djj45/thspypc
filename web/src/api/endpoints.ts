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
} from '../types'

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
  ) =>
    getJson<Kline[]>(
      `/api/kline/${code}?period=${period}&count=${count}&fuquan=${fuquan}`,
    ),
  timeline: (code: string) => getJson<TimelinePoint[]>(`/api/timeline/${code}`),
  historyTimeline: (code: string, date: string) =>
    getJson<TimelinePoint[]>(`/api/history_timeline/${code}?date=${date}`),
  auction: (code: string) => getJson<AuctionPoint[]>(`/api/auction/${code}`),
  closingAuction: (code: string) =>
    getJson<AuctionPoint[]>(`/api/closing_auction/${code}`),
  intraday: (code: string) => getJson<AuctionPoint[]>(`/api/intraday/${code}`),

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
