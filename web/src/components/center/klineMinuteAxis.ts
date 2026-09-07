import { useEffect, useState } from 'react'
import type { UTCTimestamp } from 'lightweight-charts'
import { api } from '../../api/endpoints'
import type { Kline } from '../../types'

/** 日边界阈值：相邻 bar_index 差值超过它即跨交易日。实测午休差值
 *  1min=99 / 5min=103 / 60min=162，隔夜（工作日）≥1758、周末 ~5800，
 *  取 240 对所有周期都留足余量。 */
const DAY_GAP = 240
/** 午休阈值：日内差值 >90 视为跨越 11:30-13:00 */
const LUNCH_GAP = 90

export interface DailyBar {
  date: string // 'YYYY-MM-DD'
  volume: number
}

export interface MinuteBarMeta {
  /** 真实交易日 'YYYY-MM-DD'（由日K成交量对齐得出） */
  date: string
  /** 日内时刻 'HH:mm'（按周期与实际差值近似重构） */
  clock: string
  /** 十字线用 'MM-DD HH:mm' */
  full: string
}

export interface MinuteAxis {
  /** 合成等距时间轴：首根锚定真实日期 09:30（UTC 语义），之后每根 +60s。
   *  日内/隔夜全部等距（同花顺压缩式排版）；真实日期与时
   *  刻由 metas + 日分隔线标签表达，轴刻度/十字线均走自定义 formatter。 */
  times: UTCTimestamp[]
  metas: MinuteBarMeta[]
  /** 每个交易日第一根 bar 的下标（下标 0 恒为首日），画分隔线用 */
  dayStarts: number[]
}

function pad2(n: number): string {
  return String(n).padStart(2, '0')
}

function clockOf(minuteOfDay: number): string {
  const m = Math.min(Math.max(minuteOfDay, 0), 15 * 60)
  return `${pad2(Math.floor(m / 60))}:${pad2(m % 60)}`
}

/** bar_index → 日分组：返回每组在 rows 里的下标列表（旧→新） */
function dayGroups(bars: number[]): number[][] {
  if (!bars.length) return []
  const groups: number[][] = [[0]]
  for (let i = 1; i < bars.length; i++) {
    if (bars[i] - bars[i - 1] > DAY_GAP) groups.push([])
    groups[groups.length - 1].push(i)
  }
  return groups
}

function prevTradingDay(date: string): string {
  const [y, m, d] = date.split('-').map(Number)
  const cur = new Date(Date.UTC(y, m - 1, d))
  do {
    cur.setUTCDate(cur.getUTCDate() - 1)
  } while (cur.getUTCDay() === 0 || cur.getUTCDay() === 6)
  return cur.toISOString().slice(0, 10)
}

/** 用日K的真实日期标注每个分钟日分组。
 *  分钟按天汇总成交量与日K成交量同源同单位（完整交易日精确相等）。
 *  最新一组直接锚定最新日K（同一数据源，盘中两边同步增长，不依赖
 *  严格量匹配；唯一例外是集合竞价早期日K先出现今日最小bar而分钟
 *  还是昨日——此时最新组会与倒数第二根日K精确匹配，回退一根）。
 *  中间组按量精确对齐，遇到不匹配的日K（停牌平盘日）跳过；最旧一组
 *  可能被窗口截断（量偏小），直接取当前游标。未对齐到的组从相邻
 *  日期跳过周末回推（法定假日无法离线判定，误差一天）。 */
function alignDates(groups: number[][], rows: Kline[], daily: DailyBar[] | null): string[] {
  const count = groups.length
  const dates: (string | null)[] = new Array(count).fill(null)
  if (daily && daily.length && count) {
    const volOf = (g: number) =>
      groups[g].reduce((acc, i) => acc + (rows[i].volume || 0), 0)
    let db = daily.length - 1
    const newestSum = volOf(count - 1)
    if (
      db > 0 &&
      Math.abs(daily[db].volume - newestSum) > newestSum * 0.02 &&
      Math.abs(daily[db - 1].volume - newestSum) <= Math.max(1, newestSum * 0.005)
    ) {
      db--
    }
    dates[count - 1] = daily[db].date
    db--
    for (let g = count - 2; g >= 1 && db >= 0; g--) {
      const sum = volOf(g)
      const tol = Math.max(1, sum * 0.005)
      while (db >= 0 && Math.abs(daily[db].volume - sum) > tol) db--
      if (db < 0) break
      dates[g] = daily[db].date
      db--
    }
    if (db >= 0) dates[0] = daily[db].date
  }
  // 兜底回推：未对齐的组从更新一侧的已知日期往回跳周末
  for (let g = count - 2; g >= 0; g--) {
    if (dates[g] === null && dates[g + 1]) dates[g] = prevTradingDay(dates[g + 1]!)
  }
  // 最新一组也可能没对齐到（日K加载失败）：从旧一侧已知日期前推
  for (let g = 1; g < count; g++) {
    if (dates[g] === null && dates[g - 1]) dates[g] = dates[g - 1]!
  }
  return dates.map((d, i) => d ?? '')
}

/** 组内每根 bar 的日内时刻：早盘 09:30 起、跨午休切 13:00，按实际
 *  bar_index 差值推进（无成交的小缺口按实际差值跳过，时刻略有近似）。 */
function groupClocks(bars: number[], idxs: number[], periodMinutes: number): string[] {
  const out: string[] = []
  let afternoon = false
  let ordinal = 0
  for (let k = 0; k < idxs.length; k++) {
    if (k > 0) {
      const delta = bars[idxs[k]] - bars[idxs[k - 1]]
      if (delta > LUNCH_GAP) {
        afternoon = true
        ordinal = 0
      } else {
        ordinal += Math.max(1, Math.round(delta / periodMinutes))
      }
    }
    const start = afternoon ? 13 * 60 : 9 * 60 + 30
    out.push(clockOf(start + ordinal * periodMinutes))
  }
  return out
}

export function buildMinuteAxis(
  rows: Kline[],
  periodMinutes: number,
  daily: DailyBar[] | null,
): MinuteAxis {
  if (!rows.length) return { times: [], metas: [], dayStarts: [] }
  const bars = rows.map((r) => r.bar_index ?? 0)
  const groups = dayGroups(bars)
  const dates = alignDates(groups, rows, daily)
  const first = dates[0] || '1970-01-01'
  const [y, m, d] = first.split('-').map(Number)
  const base = Date.UTC(y, m - 1, d, 9, 30) / 1000
  const times: UTCTimestamp[] = rows.map((_, i) => (base + i * 60) as UTCTimestamp)
  const metas: MinuteBarMeta[] = rows.map(() => ({
    date: '',
    clock: '',
    full: '',
  }))
  for (let gi = 0; gi < groups.length; gi++) {
    const group = groups[gi]
    const clocks = groupClocks(bars, group, periodMinutes)
    for (let k = 0; k < group.length; k++) {
      const i = group[k]
      const date = dates[gi] || ''
      const clock = clocks[k]
      metas[i] = {
        date,
        clock,
        full: `${date.slice(5)} ${clock}`,
      }
    }
  }
  return { times, metas, dayStarts: groups.map((g) => g[0]) }
}

/** 分钟K日期对齐用的日K（真实日期 + 成交量）；api 层有 TTL 缓存，
 *  切股/切周期重复请求代价低。日K数量按周期折算天数 + 余量。 */
export function useMinuteDailyBars(
  code: string,
  isMinute: boolean,
  periodMinutes: number,
): DailyBar[] | null {
  const [daily, setDaily] = useState<DailyBar[] | null>(null)
  useEffect(() => {
    if (!isMinute) return
    let alive = true
    setDaily(null)
    const days = Math.min(
      130,
      Math.max(30, Math.ceil((320 * periodMinutes) / 240) + 10),
    )
    api
      .kline(code, 'day', days, '', 'level2')
      .then((rows) => {
        if (!alive) return
        setDaily(
          rows
            .map((r) => ({ date: r.time?.slice(0, 10) ?? '', volume: r.volume || 0 }))
            .filter((item) => item.date),
        )
      })
      .catch(() => {
        if (alive) setDaily(null)
      })
    return () => {
      alive = false
    }
  }, [code, isMinute, periodMinutes])
  return daily
}
