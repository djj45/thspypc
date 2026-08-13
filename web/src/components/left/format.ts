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

// 沪/深 A 股 + 科创/创业板：list_quotes 支持的行情市场（与后端 market_from_code 对齐）。
// ETF(51x/15x/16x/18x)、基金(40x/43x)、北交所(8x/920)、新三板(830-839) 等
// list_quotes/kline/intraday 不支持，点击会超时/502，故在左栏过滤掉。
const QUOTEABLE_PREFIXES = [
  '600', '601', '603', '605', '688', '689',
  '000', '001', '002', '003', '300', '301',
]
export function isQuoteable(code: string): boolean {
  return QUOTEABLE_PREFIXES.includes(code.slice(0, 3))
}
