// 左栏面板通用格式化/着色小工具。

export function clsOf(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return 'flat'
  return n > 0 ? 'up' : n < 0 ? 'down' : 'flat'
}

export function fmtPct(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return '-'
  return (n > 0 ? '+' : '') + n.toFixed(2) + '%'
}

export function fmtAmt(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return '-'
  const abs = Math.abs(n)
  const sign = n < 0 ? '-' : ''
  if (abs >= 1e8) return sign + (abs / 1e8).toFixed(2) + '亿'
  if (abs >= 1e4) return sign + (abs / 1e4).toFixed(1) + '万'
  return n.toFixed(0)
}

export function fmtNum(n: number | null | undefined, digits = 2): string {
  if (n == null || Number.isNaN(n)) return '-'
  return n.toFixed(digits)
}

// 沪/深 A 股 + 科创/创业板 + 北交所（920xxx）：行情/K线/分时均已支持。
// ETF(51x/15x/16x/18x)、基金(40x/43x)、新三板(830-839) 等仍不支持
// （list_quotes/kline/intraday 会超时/502），在左栏过滤掉。
// 北交所旧代码 43x/83x/87x 已迁移到 920xxx；83x 与新三板 830-839 重叠，
// 故只放行 920 前缀（2026-09-08：quotes_ext/market_view/kline/intraday
// 对 920 实测有数据，"北交所"动态板块此前被整块过滤为空）。
const QUOTEABLE_PREFIXES = [
  '600', '601', '603', '605', '688', '689',
  '000', '001', '002', '003', '300', '301',
  '920',
]
export function isQuoteable(code: string): boolean {
  return QUOTEABLE_PREFIXES.includes(code.slice(0, 3))
}
