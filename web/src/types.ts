// ── 连接 / 状态 ──
export interface PreheatMarket {
  ready?: boolean
  initialized?: boolean
  skipped?: boolean
  error?: string
}
export interface Status {
  connected: boolean
  server: string
  account_kind: string
  credentials: boolean
  preheat?: {
    state: 'not_started' | 'running' | 'ready' | 'partial' | 'skipped' | 'error'
    elapsed_ms?: number
    markets?: Record<string, PreheatMarket>
    error?: string
  }
}

// ── 个股行情（list_quotes 返回，dt 字段语义见 docs）──
// dt6=昨收 dt7=今开 dt8=高 dt9=低 dt10=现价 dt13=量 dt19=额 dt48=涨速 dt66=涨幅%
export interface Quote {
  code: string
  dt6?: number
  dt7?: number
  dt8?: number
  dt9?: number
  dt10?: number
  dt13?: number
  dt19?: number
  dt48?: number
  dt66?: number
  [k: string]: number | string | undefined
}

// ── 盘口 ──
export interface DepthLevel {
  level: string
  price: number
  qty: number
  amount: number
}
export interface Depth {
  code: string
  buy: DepthLevel[]
  sell: DepthLevel[]
  seal_amount?: number
  seal_type?: string | null
  fields?: Record<string, number>
}

// ── K线 ──
export interface Kline {
  code: string
  time: string
  open: number
  high: number
  low: number
  close: number
  volume: number
  amount: number
}

// ── 分时点（个股/指数，字段较多，按需取）──
export interface TimelinePoint {
  code?: string
  bar_index?: number
  dt10?: number // 现价
  dt13?: number // 量
  dt19?: number // 额
  dt40?: number | null
  lead_price?: number // 黄均线（指数）
  [k: string]: number | string | null | undefined
}

// 竞价点（auction 早盘 / closing_auction 尾盘；time 为 ISO 字符串）
export interface AuctionPoint {
  time?: string
  dt10?: number // 撮合价 / 现价
  dt49?: number // 累计量
  dt27?: number | null // 买未匹配
  dt33?: number | null // 卖未匹配
  phase?: string
  [k: string]: number | string | null | undefined
}

export interface MarketView {
  code: string
  period: string
  fuquan: string
  quote: Quote | null
  intraday: (AuctionPoint & TimelinePoint)[]
  kline: Kline[]
  depth: Depth
}

export interface MarketViewFast {
  code: string
  quote: Quote | null
  depth: Depth
}

// ── 板块（hot_boards）──
export interface Board {
  code: string
  name?: string
  pre_close?: number
  price?: number
  chg_pct?: number
  limit_up?: number
  up_count?: number
  down_count?: number
  speed_4m?: number
  speed_1m?: number
  main_inflow?: number
  [k: string]: number | string | undefined
}

// ── 板块分类 ──
export interface BoardCategory {
  id: string
  file_id: string
  name: string
  source: string
  board_count: number
}

// ── 系统板块（list_system_blocks）──
export interface SystemBlock {
  block_id: string
  name: string
  category: string
  category_name: string
  source: string
  parent_id: string | null
}

// ── 排序榜条目（stock_list_ranked / dde_rank）──
export interface RankItem {
  code: string
  name: string
  market: number
  value?: number
  sort_by?: number
  response_field?: number
  // with_values=True 时按 sort_by 出现的 dt<N> 字段：
  dt200?: number // 涨幅
  dt48?: number // 涨速
  dt250?: number // 主力
  dt150?: number // 竞价金额
  dt154?: number // 竞价涨幅
  dt44?: number // 封单额
  [k: string]: number | string | undefined
}

// ── 全市场代码表（/api/stocks2）──
export interface StockListItem {
  code: string
  name: string
  market: number | null
}

// ── 短线精灵 ──
export interface Dxjl {
  时间: number
  市场: string
  代码: string
  异动类型: string
  异动编码: number
  金额: number
  涨跌幅: number
}

// ── 自选 / 自定义板块 ──
export interface StockItem {
  code: string
  market: string
  price: number | null
  added_at: string | null
}
export interface StockGroup {
  name: string
  group_id: string
  items: StockItem[]
  is_dynamic: boolean
}

// ── sort_by 常量（与后端 SORT_BY_VALUES 对应，活网验证）──
export const SORT_BY = {
  chg: 199112, // 涨幅 → dt200
  speed: 48, // 涨速 → dt48
  turnover: 1968584, // 换手率
  volume_ratio: 1771976, // 量比
  main_inflow: 592890, // 主力净流入 → dt250
  auction_amount: 68758, // 竞价金额 → dt150
  auction_chg: 68762, // 竞价涨幅 → dt154
  seal: 265260, // 封单额 → dt44
} as const

// sort_by → 响应里数值所在的 dt 字段名（with_values=True 时取值用）
export const SORT_BY_DT: Record<number, string> = {
  199112: 'dt200',
  48: 'dt48',
  592890: 'dt250',
  68758: 'dt150',
  68762: 'dt154',
  265260: 'dt44',
}

// 统一列表字段（/api/quotes_ext）：涨幅/竞价列由后端从 dt6/7/10/17 派生，
// 主力/DDE/市值来自 0xc4 金额表（dt250 元 / dt248 亿 / dt202 元）。
export interface QuoteExt {
  code: string
  price: number | null
  chg_pct: number | null
  auction_chg_pct: number | null
  auction_amount: number | null
  amount: number | null
  speed_4m: number | null
  main_inflow: number | null
  dde_main: number | null
  market_cap: number | null
}
